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
)

func GenerateMockPKToken(t *testing.T, signingKey crypto.Signer, alg jwa.KeyAlgorithm) (*pktoken.PKToken, error) {
	signGQ := false
	return GenerateMockPKTokenWithEmail(t, signingKey, alg, signGQ, "")
}

func GenerateMockPKTokenGQ(t *testing.T, signingKey crypto.Signer, alg jwa.KeyAlgorithm) (*pktoken.PKToken, error) {
	signGQ := true
	return GenerateMockPKTokenWithEmail(t, signingKey, alg, signGQ, "")
}

func GenerateMockPKTokenWithEmail(t *testing.T, signingKey crypto.Signer, alg jwa.KeyAlgorithm, signGQ bool, email string) (*pktoken.PKToken, error) {

	jwkKey, err := jwk.PublicKeyOf(signingKey)
	if err != nil {
		return nil, err
	}
	err = jwkKey.Set(jwk.AlgorithmKey, alg)
	if err != nil {
		return nil, err
	}

	if email != "" {
		err = jwkKey.Set("email", email)
		if err != nil {
			return nil, err
		}
	}

	cic, err := clientinstance.NewClaims(jwkKey, map[string]any{})
	if err != nil {
		return nil, err
	}

	// Generate mock id token
	op, err := mocks.NewMockOpenIdProvider(t, map[string]any{})
	if err != nil {
		return nil, err
	}

	// idToken in memguard LockedBuffer
	idToken, err := op.RequestTokens(context.Background(), cic)
	if err != nil {
		return nil, err
	}

	// Sign mock id token payload with cic headers
	cicToken, err := cic.Sign(signingKey, jwkKey.Algorithm(), idToken)
	if err != nil {
		return nil, err
	}

	// Combine two tokens into a PK Token
	return pktoken.New(idToken, cicToken)
}
