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

package jwx

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/openpubkey/openpubkey/jose"
	"github.com/stretchr/testify/require"
)

func TestFromJoseAlgorithm(t *testing.T) {
	tests := []struct {
		name           string
		joseAlg        jose.KeyAlgorithm
		expectedJwaAlg jwa.KeyAlgorithm
		expectedFound  bool
	}{
		{
			name:           "ES256",
			joseAlg:        jose.ES256,
			expectedJwaAlg: jwa.ES256(),
			expectedFound:  true,
		},
		{
			name:           "ES256K",
			joseAlg:        jose.ES256K,
			expectedJwaAlg: jwa.ES256K(),
			expectedFound:  true,
		},
		{
			name:           "ES384",
			joseAlg:        jose.ES384,
			expectedJwaAlg: jwa.ES384(),
			expectedFound:  true,
		},
		{
			name:           "ES512",
			joseAlg:        jose.ES512,
			expectedJwaAlg: jwa.ES512(),
			expectedFound:  true,
		},
		{
			name:           "EdDSA",
			joseAlg:        jose.EdDSA,
			expectedJwaAlg: jwa.EdDSA(),
			expectedFound:  true,
		},
		{
			name:           "HS256",
			joseAlg:        jose.HS256,
			expectedJwaAlg: jwa.HS256(),
			expectedFound:  true,
		},
		{
			name:           "HS384",
			joseAlg:        jose.HS384,
			expectedJwaAlg: jwa.HS384(),
			expectedFound:  true,
		},
		{
			name:           "HS512",
			joseAlg:        jose.HS512,
			expectedJwaAlg: jwa.HS512(),
			expectedFound:  true,
		},
		{
			name:           "PS256",
			joseAlg:        jose.PS256,
			expectedJwaAlg: jwa.PS256(),
			expectedFound:  true,
		},
		{
			name:           "PS384",
			joseAlg:        jose.PS384,
			expectedJwaAlg: jwa.PS384(),
			expectedFound:  true,
		},
		{
			name:           "PS512",
			joseAlg:        jose.PS512,
			expectedJwaAlg: jwa.PS512(),
			expectedFound:  true,
		},
		{
			name:           "RS256",
			joseAlg:        jose.RS256,
			expectedJwaAlg: jwa.RS256(),
			expectedFound:  true,
		},
		{
			name:           "RS384",
			joseAlg:        jose.RS384,
			expectedJwaAlg: jwa.RS384(),
			expectedFound:  true,
		},
		{
			name:           "RS512",
			joseAlg:        jose.RS512,
			expectedJwaAlg: jwa.RS512(),
			expectedFound:  true,
		},
		{
			name:           "None",
			joseAlg:        jose.None,
			expectedJwaAlg: jwa.NoSignature(),
			expectedFound:  true,
		},
		{
			name:           "Unknown algorithm",
			joseAlg:        jose.KeyAlgorithm("UNKNOWN"),
			expectedJwaAlg: jwa.KeyAlgorithm(jwa.SignatureAlgorithm{}),
			expectedFound:  false,
		},
		{
			name:           "GQ256 (not in jwa standard)",
			joseAlg:        jose.GQ256,
			expectedJwaAlg: jwa.KeyAlgorithm(jwa.SignatureAlgorithm{}),
			expectedFound:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotJwaAlg, gotFound := FromJoseAlgorithm(tt.joseAlg)

			require.Equal(t, tt.expectedFound, gotFound, "found flag should match")
			if tt.expectedFound {
				require.Equal(t, tt.expectedJwaAlg, gotJwaAlg, "algorithm should match")
			} else {
				// When not found, jwa returns a zero-value SignatureAlgorithm with empty string
				require.Equal(t, "", gotJwaAlg.String(), "algorithm string should be empty when not found")
			}
		})
	}
}

func TestToJoseAlgorithm(t *testing.T) {
	tests := []struct {
		name           string
		jwaAlg         jwa.KeyAlgorithm
		expectedJoseAlg jose.KeyAlgorithm
	}{
		{
			name:           "ES256",
			jwaAlg:         jwa.ES256(),
			expectedJoseAlg: jose.ES256,
		},
		{
			name:           "ES256K",
			jwaAlg:         jwa.ES256K(),
			expectedJoseAlg: jose.ES256K,
		},
		{
			name:           "ES384",
			jwaAlg:         jwa.ES384(),
			expectedJoseAlg: jose.ES384,
		},
		{
			name:           "ES512",
			jwaAlg:         jwa.ES512(),
			expectedJoseAlg: jose.ES512,
		},
		{
			name:           "EdDSA",
			jwaAlg:         jwa.EdDSA(),
			expectedJoseAlg: jose.EdDSA,
		},
		{
			name:           "HS256",
			jwaAlg:         jwa.HS256(),
			expectedJoseAlg: jose.HS256,
		},
		{
			name:           "HS384",
			jwaAlg:         jwa.HS384(),
			expectedJoseAlg: jose.HS384,
		},
		{
			name:           "HS512",
			jwaAlg:         jwa.HS512(),
			expectedJoseAlg: jose.HS512,
		},
		{
			name:           "PS256",
			jwaAlg:         jwa.PS256(),
			expectedJoseAlg: jose.PS256,
		},
		{
			name:           "PS384",
			jwaAlg:         jwa.PS384(),
			expectedJoseAlg: jose.PS384,
		},
		{
			name:           "PS512",
			jwaAlg:         jwa.PS512(),
			expectedJoseAlg: jose.PS512,
		},
		{
			name:           "RS256",
			jwaAlg:         jwa.RS256(),
			expectedJoseAlg: jose.RS256,
		},
		{
			name:           "RS384",
			jwaAlg:         jwa.RS384(),
			expectedJoseAlg: jose.RS384,
		},
		{
			name:           "RS512",
			jwaAlg:         jwa.RS512(),
			expectedJoseAlg: jose.RS512,
		},
		{
			name:           "None",
			jwaAlg:         jwa.NoSignature(),
			expectedJoseAlg: jose.None,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotJoseAlg := ToJoseAlgorithm(tt.jwaAlg)
			require.Equal(t, tt.expectedJoseAlg, gotJoseAlg, "algorithm should match")
		})
	}
}

func TestFromJoseAlgorithmToJoseAlgorithmRoundTrip(t *testing.T) {
	// Test that converting from jose to jwa and back preserves the value
	// for algorithms that are supported by both
	joseAlgorithms := []jose.KeyAlgorithm{
		jose.ES256,
		jose.ES256K,
		jose.ES384,
		jose.ES512,
		jose.EdDSA,
		jose.HS256,
		jose.HS384,
		jose.HS512,
		jose.PS256,
		jose.PS384,
		jose.PS512,
		jose.RS256,
		jose.RS384,
		jose.RS512,
		jose.None,
	}

	for _, joseAlg := range joseAlgorithms {
		t.Run(string(joseAlg), func(t *testing.T) {
			jwaAlg, found := FromJoseAlgorithm(joseAlg)
			if !found {
				// Skip algorithms that don't have a jwa equivalent
				t.Skipf("algorithm %s not found in jwa", joseAlg)
			}

			// Convert back to jose
			gotJoseAlg := ToJoseAlgorithm(jwaAlg)
			require.Equal(t, joseAlg, gotJoseAlg, "round trip should preserve algorithm")
		})
	}
}

