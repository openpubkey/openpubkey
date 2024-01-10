// Copyright 2024 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package providers

import (
	"context"
	"crypto"
	"time"

	"github.com/awnumar/memguard"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/jwt/openid"
	"github.com/openpubkey/openpubkey/util"
)

const (
	MockIssuer   = "me"
	MockAudience = "also_me"
)

type MockOpenIdProvider struct {
	alg    jwa.KeyAlgorithm
	signer crypto.Signer
}

func NewMockOpenIdProvider() (*MockOpenIdProvider, error) {
	alg := jwa.RS256
	signingKey, err := util.GenKeyPair(alg)
	if err != nil {
		return nil, err
	}

	return &MockOpenIdProvider{
		alg:    alg,
		signer: signingKey,
	}, nil
}

func (m *MockOpenIdProvider) RequestTokens(ctx context.Context, cicHash string) (*memguard.LockedBuffer, error) {
	token := openid.New()

	token.Set("nonce", cicHash)
	token.Set("email", "arthur.aardvark@example.com")

	// Required token payload values for OpenID
	token.Set(jwt.IssuerKey, MockIssuer)
	token.Set(jwt.AudienceKey, MockAudience)
	token.Set(jwt.IssuedAtKey, time.Now().Unix())
	token.Set(jwt.ExpirationKey, time.Now().Add(24*time.Hour).Unix())
	token.Set(jwt.SubjectKey, "1234567890")

	// Sign the token with the secret key
	signedToken, err := jwt.Sign(token, jwt.WithKey(m.alg, m.signer))
	if err != nil {
		return nil, err
	}
	return memguard.NewBufferFromBytes(signedToken), nil
}

func (m *MockOpenIdProvider) Issuer() string {
	return MockIssuer
}

func (m *MockOpenIdProvider) PublicKey(ctx context.Context, headers jws.Headers) (crypto.PublicKey, error) {
	return m.signer.Public(), nil
}

func (m *MockOpenIdProvider) VerifyCICHash(ctx context.Context, idt []byte, expectedCICHash string) error {
	return nil
}

func (m *MockOpenIdProvider) VerifyNonGQSig(ctx context.Context, idt []byte, expectedNonce string) error {
	return nil
}
