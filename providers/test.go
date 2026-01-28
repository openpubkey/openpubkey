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
	"crypto"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/openpubkey/openpubkey/jose"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/testutils"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func GenCIC(t *testing.T) *clientinstance.Claims {
	return GenCICExtra(t, map[string]any{})
}

func GenCICExtra(t *testing.T, extraClaims map[string]any) *clientinstance.Claims {
	alg := jose.ES256
	signer, err := util.GenKeyPair(alg)
	require.NoError(t, err)
	return GenCICEverything(t, extraClaims, signer, alg)
}

func GenCICEverything(t *testing.T, extraClaims map[string]any, signer crypto.Signer, alg string) *clientinstance.Claims {
	jwkKey, err := jwk.PublicKeyOf(signer)
	require.NoError(t, err)
	err = jwkKey.Set(jwk.AlgorithmKey, alg)
	require.NoError(t, err)
	cic, err := clientinstance.NewClaims(jwkKey, extraClaims)
	require.NoError(t, err)
	return cic
}

// GenCICDeterministic generates a CIC using a fixed key pair for testing purposes.
// Only use in tests. This would be wildly insecure in production as the secret key is a public value.
func GenCICDeterministic(t *testing.T, extraClaims map[string]any) (*clientinstance.Claims, crypto.Signer, string) {
	alg := "ES256"
	signer := testutils.DeterministicTestKeyPair(t, alg)
	cic := GenCICEverything(t, extraClaims, signer, alg)
	return cic, signer, alg
}
