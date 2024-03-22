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
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/openpubkey/openpubkey/client/mocks"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func GenerateMockPKToken(t *testing.T, signingKey crypto.Signer, alg jwa.KeyAlgorithm) (*pktoken.PKToken, error) {
	return GenerateMockPKTokenWithOpts(t, signingKey, alg, map[string]any{})
}

func GenerateMockPKTokenGQ(t *testing.T, signingKey crypto.Signer, alg jwa.KeyAlgorithm) (*pktoken.PKToken, error) {
	return GenerateMockPKTokenWithOpts(t, signingKey, alg, map[string]any{}, UseGQSign(true))
}

type MockPKTokenOpts struct {
	GQSign         bool
	GQCommitment   bool
	GQOnly         bool
	CorrectCicHash bool
	CorrectCicSig  bool
}
type Opts func(a *MockPKTokenOpts)

// Example use:
//
//	UseGQSign(true)
func UseGQSign(gqSign bool) Opts {
	return func(m *MockPKTokenOpts) {
		m.GQSign = gqSign
	}
}

// UseGQCommitment specifies whether the commitment binding should be a GQ
// binding or a claim based binding.
// Example use:
//
//	UseGQCommitment(true)
func UseGQCommitment(gqCommitment bool) Opts {
	return func(m *MockPKTokenOpts) {
		m.GQCommitment = gqCommitment
	}
}

// Example use:
//
//	UseGQOnly(true)
func UseGQOnly(gqOnly bool) Opts {
	return func(m *MockPKTokenOpts) {
		m.GQOnly = gqOnly
	}
}

func CorrectCicHash(correctCicHash bool) Opts {
	return func(m *MockPKTokenOpts) {
		m.CorrectCicHash = correctCicHash
	}
}

func CorrectCicSig(correctCicSig bool) Opts {
	return func(m *MockPKTokenOpts) {
		m.CorrectCicSig = correctCicSig
	}
}

func GenerateMockPKTokenWithOpts(t *testing.T, signingKey crypto.Signer, alg jwa.KeyAlgorithm,
	extraClaims map[string]any, opts ...Opts) (*pktoken.PKToken, error) {

	options := &MockPKTokenOpts{
		GQSign:         false,
		GQCommitment:   false,
		CorrectCicHash: true,
		CorrectCicSig:  true,
	}
	for _, applyOpt := range opts {
		applyOpt(options)
	}

	jwkKey, err := jwk.PublicKeyOf(signingKey)
	if err != nil {
		return nil, err
	}
	err = jwkKey.Set(jwk.AlgorithmKey, alg)
	if err != nil {
		return nil, err
	}

	cic, err := clientinstance.NewClaims(jwkKey, map[string]any{})
	if err != nil {
		return nil, err
	}

	// Set gqOnly to gqCommitment since gqCommitment requires gqOnly
	gqOnly := options.GQCommitment

	// Generate mock id token
	op, err := mocks.NewMockOpenIdProvider(t, extraClaims,
		mocks.UseGQSign(options.GQSign),
		mocks.UseGQCommitment(options.GQCommitment),
		mocks.UseGQOnly(gqOnly))
	if err != nil {
		return nil, err
	}

	idToken, err := op.RequestTokens(context.Background(), cic)
	if err != nil {
		return nil, err
	}

	// Return a PK Token where the CIC which doesn't match the commitment
	if !options.CorrectCicHash {
		// overwrite the cic with a new cic with a different hash
		cic, err = clientinstance.NewClaims(jwkKey, map[string]any{"cause": "differentCicHash"})
		if err != nil {
			return nil, err
		}
	}

	// Return a PK Token where the CIC that is signed by the wrong key
	if !options.CorrectCicSig {
		// overwrite the signkey with a new key
		signingKey, err = util.GenKeyPair(alg)
		require.NoError(t, err)

		jwkKey, err = jwk.PublicKeyOf(signingKey)
		if err != nil {
			return nil, err
		}
		err = jwkKey.Set(jwk.AlgorithmKey, alg)
		if err != nil {
			return nil, err
		}
	}

	// Sign mock id token payload with cic headers
	cicToken, err := cic.Sign(signingKey, jwkKey.Algorithm(), idToken)
	if err != nil {
		return nil, err
	}

	// Combine two tokens into a PK Token
	return pktoken.New(idToken, cicToken)
}
