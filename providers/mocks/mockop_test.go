// Copyright 2025 OpenPubkey
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

package mocks

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestMockOp(t *testing.T) {
	issuer := "https://issuer.example.com"
	clientId := "test-client-id"

	idp, err := NewMockOp(issuer, []Subject{
		{
			SubjectID: "alice@example.com",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, idp)

	expSigningKey, expKeyID, expRecord := idp.RandomSigningKey()
	idp.MockProviderBackend.IDTokenTemplate = &IDTokenTemplate{
		CommitFunc: AddNonceCommit,
		Issuer:     issuer,
		Nonce:      "empty",
		NoNonce:    false,
		Aud:        clientId,
		KeyID:      expKeyID,
		NoKeyID:    false,
		Alg:        expRecord.Alg,
		NoAlg:      false,
		SigningKey: expSigningKey,
	}

	subject := Subject{
		SubjectID: "alice@example.com",
	}

	rt := idp.GetHTTPClient()
	require.NotNil(t, rt)
	jkt := "" // No key binding in this test
	require.Contains(t, idp.CreateAuthCode("test-nonce", &subject, jkt), "fake-auth-code-")
}

func TestValidateDPoPJwk(t *testing.T) {
	testCases := []struct {
		name     string
		alg      string
		expError string
	}{
		{name: "Happy case (ES256)", alg: "ES256", expError: ""},
		{name: "Happy case (EdDSA)", alg: "EdDSA", expError: ""},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signer := DeterministicTestKeyPair(t, tc.alg)
			jwkKey, err := jwk.FromRaw(signer.Public())
			require.NoError(t, err, tc.name)

			err = jwkKey.Set(jwk.AlgorithmKey, tc.alg)
			require.NoError(t, err, tc.name)

			// Compute the JWK Thumbprint (JKT)
			jkt, err := jwkKey.Thumbprint(crypto.SHA256)
			require.NoError(t, err, tc.name)
			jktb64 := util.Base64EncodeForJWT(jkt)

			jwkJSON, err := json.Marshal(jwkKey)
			require.NoError(t, err, tc.name)

			auth_code := "SplxlOBeZQQYbYS6WxSbIA"
			cHash := sha256.Sum256([]byte(auth_code))
			cHashB64 := base64.RawURLEncoding.EncodeToString(cHash[:])

			dpopPayload := map[string]any{
				"c_hash": cHashB64,
				"htm":    "POST",
				"htu":    "https://issuer.hello.coop/token",
				"iat":    1764619470,
				"jti":    "y3MzLWnhkw3dYSfBvSykEw",
			}

			payloadJson, err := json.Marshal(dpopPayload)
			require.NoError(t, err)

			headers := jws.NewHeaders()
			err = headers.Set("typ", "dpop+jwt")
			require.NoError(t, err, tc.name)
			err = headers.Set("alg", tc.alg)
			require.NoError(t, err, tc.name)
			err = headers.Set("jwk", jwkKey)
			require.NoError(t, err, tc.name)

			jwsDpopCompact, err := jws.Sign(payloadJson, jws.WithKey(jwa.KeyAlgorithmFrom(tc.alg), signer, jws.WithProtectedHeaders(headers)))
			require.NoError(t, err, tc.name)
			require.NotNil(t, jwsDpopCompact, "generated DPoP JWS is nil")

			requiredClaims := map[string]string{
				"c_hash": cHashB64,
			}

			jwkJson, err := validateDPoPJwk(string(jktb64), string(jwsDpopCompact), requiredClaims)
			require.NoError(t, err, tc.name)
			require.Equal(t, string(jwkJSON), string(jwkJson), "validated JWK does not match expected JWK", tc.name)
		})
	}
}
