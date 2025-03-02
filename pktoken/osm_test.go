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

package pktoken

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

func TestVerifySignedMessage_TypOverride(t *testing.T) {
	// Generate a test RSA key pair
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Convert RSA public key to JWK and set "alg" to RS256
	jwkKey, err := jwk.FromRaw(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to create JWK: %v", err)
	}
	if err := jwkKey.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("failed to set JWK alg: %v", err)
	}

	// Use a consistent payload for both Op and Cic
	payload := []byte("consistent payload")

	// Create a mock Cic signature with "rz" and "upk" claims
	cicProtected := jws.NewHeaders()
	cicProtected.Set(jws.AlgorithmKey, jwa.RS256)
	cicProtected.Set(jws.TypeKey, "CIC")
	cicProtected.Set("rz", "test-randomness") // Required "rz" claim
	cicProtected.Set("upk", jwkKey)           // Required "upk" claim with matching alg
	cicOsm, err := jws.Sign(payload, jws.WithKey(jwa.RS256, key, jws.WithProtectedHeaders(cicProtected)))
	if err != nil {
		t.Fatalf("failed to create mock Cic: %v", err)
	}

	// Create a mock Op signature (required by PKToken)
	opProtected := jws.NewHeaders()
	opProtected.Set(jws.AlgorithmKey, jwa.RS256)
	opProtected.Set(jws.TypeKey, "JWT") // OIDC type
	opToken, err := jws.Sign(payload, jws.WithKey(jwa.RS256, key, jws.WithProtectedHeaders(opProtected)))
	if err != nil {
		t.Fatalf("failed to create mock Op: %v", err)
	}

	// Initialize PKToken with Op and Cic signatures
	p, err := New(opToken, cicOsm)
	if err != nil {
		t.Fatalf("failed to create PKToken: %v", err)
	}

	// Get the real hash to use as "kid"
	hash, err := p.Hash()
	if err != nil {
		t.Fatalf("failed to compute PKToken hash: %v", err)
	}

	// Test 1: Verify message with "osm" typ
	osmProtected := jws.NewHeaders()
	osmProtected.Set(jws.AlgorithmKey, jwa.RS256)
	osmProtected.Set(jws.KeyIDKey, hash) // Use real hash as "kid"
	osmProtected.Set(jws.TypeKey, "osm")
	osm, err := jws.Sign([]byte("test message"), jws.WithKey(jwa.RS256, key, jws.WithProtectedHeaders(osmProtected)))
	if err != nil {
		t.Fatalf("failed to sign osm: %v", err)
	}

	result, err := p.VerifySignedMessage(osm)
	if err != nil {
		t.Errorf("expected no error for osm, got: %v", err)
	}
	if string(result) != "test message" {
		t.Errorf("expected 'test message', got: %s", result)
	}

	// Test 2: Verify message with "JWT" typ
	jwtProtected := jws.NewHeaders()
	jwtProtected.Set(jws.AlgorithmKey, jwa.RS256)
	jwtProtected.Set(jws.KeyIDKey, hash) // Use real hash as "kid"
	jwtProtected.Set(jws.TypeKey, "JWT")
	jwtOsm, err := jws.Sign([]byte("jwt message"), jws.WithKey(jwa.RS256, key, jws.WithProtectedHeaders(jwtProtected)))
	if err != nil {
		t.Fatalf("failed to sign JWT: %v", err)
	}

	result, err = p.VerifySignedMessage(jwtOsm, WithTyp("JWT"))
	if err != nil {
		t.Errorf("expected no error for JWT, got: %v", err)
	}
	if string(result) != "jwt message" {
		t.Errorf("expected 'jwt message', got: %s", result)
	}

	// Test 3: Verify failure without typ override
	_, err = p.VerifySignedMessage(jwtOsm) // Expects "osm" by default
	if err == nil {
		t.Error("expected error for mismatched typ")
	}
}
