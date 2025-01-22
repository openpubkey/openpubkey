// Copyright 2024 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package mocks

import (
	"context"
	"crypto"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/providers/mocks"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func GenerateMockPKToken(t *testing.T, signingKey crypto.Signer, alg jwa.KeyAlgorithm) (*pktoken.PKToken, error) {
	options := &MockPKTokenOpts{
		GQSign:         false,
		CommitType:     providers.CommitTypesEnum.NONCE_CLAIM,
		CorrectCicHash: true,
		CorrectCicSig:  true,
	}
	pkt, _, err := GenerateMockPKTokenWithOpts(t, signingKey, alg, mocks.DefaultIDTokenTemplate(), options)
	return pkt, err
}

func GenerateMockPKTokenGQ(t *testing.T, signingKey crypto.Signer, alg jwa.KeyAlgorithm) (*pktoken.PKToken, error) {
	options := &MockPKTokenOpts{
		GQSign:         true,
		CommitType:     providers.CommitTypesEnum.NONCE_CLAIM,
		CorrectCicHash: true,
		CorrectCicSig:  true,
	}
	pkt, _, err := GenerateMockPKTokenWithOpts(t, signingKey, alg, mocks.DefaultIDTokenTemplate(), options)
	return pkt, err
}

type MockPKTokenOpts struct {
	GQSign         bool
	CommitType     providers.CommitType
	GQOnly         bool
	CorrectCicHash bool
	CorrectCicSig  bool
}

func GenerateMockPKTokenWithOpts(t *testing.T, signingKey crypto.Signer, alg jwa.KeyAlgorithm,
	idtTemplate mocks.IDTokenTemplate, options *MockPKTokenOpts) (*pktoken.PKToken, *mocks.MockProviderBackend, error) {

	jwkKey, err := jwk.PublicKeyOf(signingKey)
	if err != nil {
		return nil, nil, err
	}
	err = jwkKey.Set(jwk.AlgorithmKey, alg)
	if err != nil {
		return nil, nil, err
	}

	cic, err := clientinstance.NewClaims(jwkKey, map[string]any{})
	require.NoError(t, err)

	// Set gqOnly to gqCommitment since gqCommitment requires gqOnly
	gqOnly := options.CommitType.GQCommitment

	providerOpts := providers.MockProviderOpts{
		GQSign:     options.GQSign,
		CommitType: options.CommitType,
		NumKeys:    2,
		VerifierOpts: providers.ProviderVerifierOpts{
			SkipClientIDCheck: false,
			GQOnly:            gqOnly,
			CommitType:        options.CommitType,
			ClientID:          "mockClient-ID",
		},
	}

	op, backend, _, err := providers.NewMockProvider(providerOpts)
	require.NoError(t, err)
	opSignKey, keyID, _ := backend.RandomSigningKey()
	idtTemplate.KeyID = keyID
	idtTemplate.SigningKey = opSignKey

	switch options.CommitType {
	case providers.CommitTypesEnum.NONCE_CLAIM:
		idtTemplate.CommitFunc = mocks.AddNonceCommit
	case providers.CommitTypesEnum.AUD_CLAIM:
		idtTemplate.CommitFunc = mocks.AddAudCommit
	case providers.CommitTypesEnum.GQ_BOUND:
	default:
		return nil, nil, fmt.Errorf("unknown CommitType: %v", options.CommitType)
	}

	backend.SetIDTokenTemplate(&idtTemplate)

	tokens, err := op.RequestTokens(context.Background(), cic)
	if err != nil {
		return nil, nil, err
	}
	idToken := tokens.IDToken

	// Return a PK Token where the CIC which doesn't match the commitment
	if !options.CorrectCicHash {
		// overwrite the cic with a new cic with a different hash
		cic, err = clientinstance.NewClaims(jwkKey, map[string]any{"cause": "differentCicHash"})
		if err != nil {
			return nil, nil, err
		}
	}

	// Return a PK Token where the CIC that is signed by the wrong key
	if !options.CorrectCicSig {
		// overwrite the signkey with a new key
		signingKey, err = util.GenKeyPair(alg)
		require.NoError(t, err)

		jwkKey, err = jwk.PublicKeyOf(signingKey)
		if err != nil {
			return nil, nil, err
		}
		err = jwkKey.Set(jwk.AlgorithmKey, alg)
		if err != nil {
			return nil, nil, err
		}
	}

	// Sign mock id token payload with cic headers
	cicToken, err := cic.Sign(signingKey, jwkKey.Algorithm(), idToken)
	if err != nil {
		return nil, nil, err
	}

	// Combine two tokens into a PK Token
	pkt, err := pktoken.New(idToken, cicToken)
	if err != nil {
		return nil, nil, err
	}
	return pkt, backend, nil
}
