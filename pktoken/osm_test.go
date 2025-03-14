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

package pktoken

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/stretchr/testify/require"
)

func TestVerifySignedMessage_TypOverride(t *testing.T) {
	// Generate a test RSA key pair
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Convert RSA public key to JWK and set "alg" to RS256
	jwkKey, err := jwk.FromRaw(&key.PublicKey)
	require.NoError(t, err)

	err = jwkKey.Set(jwk.AlgorithmKey, jwa.RS256)
	require.NoError(t, err, "failed to set JWK alg")

	// Use a consistent payload for both Op and Cic
	payload := []byte("consistent payload")

	// Create a mock Cic signature with "rz" and "upk" claims
	cicProtected := jws.NewHeaders()
	require.NoError(t, cicProtected.Set(jws.AlgorithmKey, jwa.RS256))
	require.NoError(t, cicProtected.Set(jws.TypeKey, "CIC"))
	require.NoError(t, cicProtected.Set("rz", "test-randomness")) // Required "rz" claim
	require.NoError(t, cicProtected.Set("upk", jwkKey))           // Required "upk" claim with matching alg
	cicOsm, err := jws.Sign(payload, jws.WithKey(jwa.RS256, key, jws.WithProtectedHeaders(cicProtected)))
	require.NoError(t, err, "failed to create mock Cic")

	// Create a mock Op signature (required by PKToken)
	opProtected := jws.NewHeaders()
	require.NoError(t, opProtected.Set(jws.AlgorithmKey, jwa.RS256))
	require.NoError(t, opProtected.Set(jws.TypeKey, "JWT")) // OIDC type
	opToken, err := jws.Sign(payload, jws.WithKey(jwa.RS256, key, jws.WithProtectedHeaders(opProtected)))
	require.NoError(t, err, "failed to create mock Op")

	// Initialize PKToken with Op and Cic signatures
	p, err := New(opToken, cicOsm)
	require.NoError(t, err, "failed to create PKToken")

	// Get the real hash to use as "kid"
	hash, err := p.Hash()
	require.NoError(t, err, "failed to compute PKToken hash")

	// Test 1: Verify message with "osm" typ
	osmProtected := jws.NewHeaders()
	require.NoError(t, osmProtected.Set(jws.AlgorithmKey, jwa.RS256))
	require.NoError(t, osmProtected.Set(jws.KeyIDKey, hash)) // Use real hash as "kid"
	require.NoError(t, osmProtected.Set(jws.TypeKey, "osm"))
	osm, err := jws.Sign([]byte("test message"), jws.WithKey(jwa.RS256, key, jws.WithProtectedHeaders(osmProtected)))
	require.NoError(t, err, "failed to create mock osm")

	result, err := p.VerifySignedMessage(osm)
	require.NoError(t, err, "expected no error for osm")

	require.Equal(t, "test message", string(result))

	// Test 2: Verify message with "JWT" typ
	jwtProtected := jws.NewHeaders()
	require.NoError(t, jwtProtected.Set(jws.AlgorithmKey, jwa.RS256))
	require.NoError(t, jwtProtected.Set(jws.KeyIDKey, hash)) // Use real hash as "kid"
	require.NoError(t, jwtProtected.Set(jws.TypeKey, "JWT"))
	jwtOsm, err := jws.Sign([]byte("jwt message"), jws.WithKey(jwa.RS256, key, jws.WithProtectedHeaders(jwtProtected)))
	require.NoError(t, err, "failed to create mock JWT")

	result, err = p.VerifySignedMessage(jwtOsm, WithTyp("JWT"))
	require.NoError(t, err, "expected no error for JWT")

	require.Equal(t, "jwt message", string(result))

	// Test 3: Verify failure without typ override
	_, err = p.VerifySignedMessage(jwtOsm) // Expects "osm" by default
	require.Error(t, err, "expected error for mismatched typ")
}
