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

package providers

import (
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestNewTestKeyPairs(t *testing.T) {

	testCases := []struct {
		name string
		alg  string
	}{
		{name: "Test creating ES256 key", alg: "ES256"},
		{name: "Test creating EdDSA key", alg: "EdDSA"},
		{name: "Test creating RS256 key", alg: "RS256"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signer, err := util.GenKeyPair(jwa.KeyAlgorithmFrom(tc.alg))
			require.NoError(t, err)

			jwkJson := NewTestKeyPairs(t, signer)
			require.NotNil(t, jwkJson)

			jwkKey, err := jwk.ParseKey(jwkJson)
			require.NoError(t, err)

			jwkKey2, err := jwk.FromRaw(signer)
			require.NoError(t, err)
			require.Equal(t, jwkKey, jwkKey2)
		})
	}

}
