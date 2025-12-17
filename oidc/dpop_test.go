// Copyright 2025 OpenPubkey
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

package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/openpubkey/openpubkey/testutils"
	"github.com/stretchr/testify/require"
)

func TestDPoPMatch(t *testing.T) {
	iatNow := time.Now().Unix()

	testCases := []struct {
		name        string
		dpopClaims  DpopClaims
		claimMap    map[string]any
		expectedErr string
	}{
		{name: "Happy path",
			dpopClaims: DpopClaims{Htm: "GET", Htu: "https://example.com/resource", Jti: "unique-jti", Iat: iatNow},
			claimMap:   map[string]any{"htm": "GET", "htu": "https://example.com/resource", "jti": "unique-jti", "iat": iatNow},
		},
		{name: "Claim doesn't match",
			dpopClaims:  DpopClaims{Htm: "GET", Htu: "https://example.com/resource", Jti: "different-jti"},
			claimMap:    map[string]any{"htm": "GET", "htu": "https://example.com/resource", "jti": "unique-jti"},
			expectedErr: "claim jti in DPoP has unexpected value, got different-jti, want unique-jti"},
		{name: "Claim doesn't exist",
			dpopClaims:  DpopClaims{Htm: "GET", Htu: "https://example.com/resource", Jti: "different-jti"},
			claimMap:    map[string]any{"cHash": "abc123"},
			expectedErr: "claim cHash not found in DPoP"},
		{name: "Claim has different type",
			dpopClaims:  DpopClaims{Htm: "GET", Htu: "https://example.com/resource", Jti: "different-jti"},
			claimMap:    map[string]any{"htm": "GET", "jti": 12345},
			expectedErr: "claim jti in DPoP has wrong type, got int, want string"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := tc.dpopClaims.MatchesClaims(tc.claimMap)
			if tc.expectedErr == "" {
				require.NoError(t, err, tc.name)
				require.True(t, ok, tc.name)
			} else {
				require.Error(t, err, tc.name)
				require.Contains(t, err.Error(), tc.expectedErr, tc.name)
				require.False(t, ok, tc.name)
			}

		})
	}
}

func TestValidateDPoPJwk(t *testing.T) {
	testCases := []struct {
		name        string
		alg         string
		dpopPayload map[string]any
		expectedErr string
	}{
		{name: "Happy case (ES256)", alg: "ES256",
			dpopPayload: map[string]any{
				"htm": "POST",
				"htu": "https://issuer.hello.coop/token",
				"iat": time.Now().Unix(),
				"jti": "y3MzLWnhkw3dYSfBvSykEw",
			},
			expectedErr: ""},
		{name: "Happy case (EdDSA)", alg: "EdDSA",
			dpopPayload: map[string]any{
				"htm": "POST",
				"htu": "https://issuer.hello.coop/token",
				"iat": time.Now().Unix(),
				"jti": "y3MzLWnhkw3dYSfBvSykEw",
			},
			expectedErr: ""},
		{name: "Expired IAT case (EdDSA)", alg: "EdDSA",
			dpopPayload: map[string]any{
				"htm": "POST",
				"htu": "https://issuer.hello.coop/token",
				"iat": time.Now().Unix() - 3600,
				"jti": "y3MzLWnhkw3dYSfBvSykEw",
			},
			expectedErr: "PoP header is expired"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signer := testutils.DeterministicTestKeyPair(t, tc.alg)
			jwkKey, err := jwk.Import(signer.Public())
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

			keyAlg, err := jwa.KeyAlgorithmFrom(tc.alg)
			require.NoError(t, err, tc.name)
			jwsDpopCompact, err := jws.Sign(payloadJson, jws.WithKey(keyAlg, signer, jws.WithProtectedHeaders(headers)))
			require.NoError(t, err, tc.name)
			require.NotNil(t, jwsDpopCompact, "generated DPoP JWS is nil")

			requiredClaims := map[string]any{
				"c_hash": cHashB64,
			}

			dpopJwt, err := NewDpopJwt(jwsDpopCompact)
			require.NoError(t, err, tc.name)

			jwkJsonRet, err := dpopJwt.GetJWKIfClaimsMatch(requiredClaims)
			if tc.expectedErr == "" {
				require.NoError(t, err, tc.name)
				require.Equal(t, string(jwkJson), string(jwkJsonRet), "validated JWK does not match expected JWK", tc.name)
			} else {
				require.Error(t, err, tc.name)
				require.Contains(t, err.Error(), tc.expectedErr, tc.name)
			}
		})
	}
}
