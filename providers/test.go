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
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func GenCIC(t *testing.T) *clientinstance.Claims {
	return GenCICExtra(t, map[string]any{})
}

func GenCICExtra(t *testing.T, extraClaims map[string]any) *clientinstance.Claims {
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	require.NoError(t, err)
	return GenCICEverything(t, extraClaims, signer, alg.String())
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

const es256keyPairJSON = `{
	"crv": "P-256",
	"d": "VkLzE5IzCxLiD3QzSiijY5CzpU0gZ7h8NECFL_MoyFQ",
	"kty": "EC",
	"x": "ukpv3fU6tqQKaUwcdBAQoK3IHvJIW__9yNd1oR7qvZc",
	"y": "nBBxXrx0Nziwg_evfUMUUgnGKKUf2ATpWG9EojnUoU4",
	"alg": "ES256"
}`

const ed25519keyPairJSON = `{
  "crv": "Ed25519",
  "d": "dvrQIDJN2SwU0xUxCux5Cdslv0N9tP6jpl7J_kqXcXA",
  "kty": "OKP",
  "x": "fmkTfA6VJtkaSZL0j9m-DRke3K9xMxxabuqLOPa-G7E"
}`

// GenCICDeterministic generates a CIC using a fixed key pair for testing purposes.
// Only use in tests. This would be wildly insecure in production as the secret key is a public value.
func GenCICDeterministic(t *testing.T, extraClaims map[string]any) (*clientinstance.Claims, crypto.Signer, string) {
	alg := "ES256"
	signer := DeterministicTestKeyPair(t, alg)
	cic := GenCICEverything(t, extraClaims, signer, alg)
	return cic, signer, alg
}

// DeterministicTestKeyPair generates a deterministic key pair for testing purposes.
// Only use in tests. This would be wildly insecure in production as the secret key is a public value.
func DeterministicTestKeyPair(t *testing.T, alg string) crypto.Signer {
	switch alg {
	case jwa.ES256.String():
		kp, err := jwk.ParseKey([]byte(es256keyPairJSON))
		require.NoError(t, err)

		var privKey ecdsa.PrivateKey
		err = kp.Raw(&privKey)
		require.NoError(t, err)

		return &privKey
	case jwa.EdDSA.String():
		kp, err := jwk.ParseKey([]byte(ed25519keyPairJSON))
		require.NoError(t, err)

		var privKey ed25519.PrivateKey
		err = kp.Raw(&privKey)
		require.NoError(t, err)

		return &privKey
	default:
		t.Fatalf("unsupported algorithm for deterministic key pair: %s", alg)
		return nil
	}
}

// NewTestKeyPairs is used for creating JSON representations of JWKs for tests.
// This is how we generate the embedded JWKs for our unittests.
func NewTestKeyPairs(t *testing.T, signer crypto.Signer) []byte {
	privJWK, err := jwk.FromRaw(signer)
	require.NoError(t, err)

	jwkJson, err := json.MarshalIndent(privJWK, "", "  ")
	require.NoError(t, err)
	return jwkJson
}
