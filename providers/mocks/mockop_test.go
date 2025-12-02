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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/testutils"
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

func TestValidateDPoPReturnJwk(t *testing.T) {
	testCases := []struct {
		name        string
		alg         string
		jkt         string
		dpopPayload map[string]any
		expectedErr string
	}{
		{name: "Happy case (ES256)", alg: "ES256",
			jkt: "dnfb1T9jil_gOhti60baHs_WD_a4D8JN9VDJXbmBmGw",
			dpopPayload: map[string]any{
				"htm": "POST",
				"htu": "https://issuer.hello.coop/token",
				"iat": time.Now().Unix(),
				"jti": "y3MzLWnhkw3dYSfBvSykEw",
			},
			expectedErr: ""},
		{name: "Happy case (EdDSA)", alg: "EdDSA",
			jkt: "Pdzg6MNo5Ns8YgL-IGl64DQLUNbN1QlWznz-skHMEPY",
			dpopPayload: map[string]any{
				"htm": "POST",
				"htu": "https://issuer.hello.coop/token",
				"iat": time.Now().Unix(),
				"jti": "y3MzLWnhkw3dYSfBvSykEw",
			},
			expectedErr: ""},
		{name: "Expired IAT case (EdDSA)", alg: "EdDSA",
			jkt: "wrongjktthumbprint",
			dpopPayload: map[string]any{
				"htm": "POST",
				"htu": "https://issuer.hello.coop/token",
				"iat": time.Now().Unix(),
				"jti": "y3MzLWnhkw3dYSfBvSykEw",
			},
			expectedErr: "JWK thumbprint mismatch"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signer := testutils.DeterministicTestKeyPair(t, tc.alg)
			jwkKey, err := jwk.FromRaw(signer.Public())
			require.NoError(t, err, tc.name)

			err = jwkKey.Set(jwk.AlgorithmKey, tc.alg)
			require.NoError(t, err, tc.name)

			jwkJson, err := json.Marshal(jwkKey)
			require.NoError(t, err, tc.name)

			authCode := "SplxlOBeZQQYbYS6WxSbIA"
			cHash := sha256.Sum256([]byte(authCode))
			cHashB64 := base64.RawURLEncoding.EncodeToString(cHash[:])

			dpopPayload := tc.dpopPayload
			dpopPayload["c_hash"] = cHashB64

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

			requiredClaims := map[string]any{
				"c_hash": cHashB64,
			}

			jwkMapRet, err := validateDPoPReturnJwk(string(jwsDpopCompact), string(tc.jkt), requiredClaims)
			if tc.expectedErr == "" {
				require.NoError(t, err, tc.name)

				jwkJsonRet, err := json.Marshal(jwkMapRet)
				require.NoError(t, err, tc.name)

				require.Equal(t, string(jwkJson), string(jwkJsonRet), "validated JWK does not match expected JWK", tc.name)
			} else {
				require.Error(t, err, tc.name)
				require.Contains(t, err.Error(), tc.expectedErr, tc.name)
			}
		})
	}
}
