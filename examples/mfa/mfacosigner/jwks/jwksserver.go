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

package jwks

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/openpubkey/openpubkey/jose"
)

type JwksServer struct {
	uri       string
	jwksBytes []byte
}

// A very simple JWKS server for our MFA Cosigner example code.
func NewJwksServer(signer crypto.Signer, alg jose.KeyAlgorithm) (*JwksServer, string, error) {
	// Compute the kid (Key ID) as the SHA-3 of the public key
	pubkey := signer.Public().(*ecdsa.PublicKey) // TODO: handle non-ecdsa signers
	ecdhPubKey, err := pubkey.ECDH()
	if err != nil {
		return nil, "", fmt.Errorf("failed to convert public key for byte extraction: %w", err)
	}
	pubkeyBytes := ecdhPubKey.Bytes()

	// Compute the kid (Key ID) as the SHA-3 of the public key
	pubkeyHash := sha3.Sum256(pubkeyBytes)
	kid := hex.EncodeToString(pubkeyHash[:])

	// Generate our JWKS using our signing key
	jwkKey, err := jwk.PublicKeyOf(signer)
	if err != nil {
		return nil, "", err
	}

	if err := jwkKey.Set(jwk.AlgorithmKey, alg); err != nil {
		return nil, "", err
	}
	if err := jwkKey.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, "", err
	}

	// Put our jwk into a set
	keySet := jwk.NewSet()
	if err := keySet.AddKey(jwkKey); err != nil {
		return nil, "", err
	}

	// Now convert our key set into the raw bytes for printing later
	keySetBytes, err := json.MarshalIndent(keySet, "", "  ")
	if err != nil {
		return nil, "", err
	}

	// Find an empty port
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, "", fmt.Errorf("failed to bind to an available port: %w", err)
	}

	server := &JwksServer{
		uri:       fmt.Sprintf("http://localhost:%d", listener.Addr().(*net.TCPAddr).Port),
		jwksBytes: keySetBytes,
	}

	// Host our JWKS at a localhost url
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", server.printJWKS)
	go func() {
		if err := http.Serve(listener, mux); err != nil && err != http.ErrServerClosed {
			log.Printf("JWKS server error: %v", err)
		}

	}()
	return server, kid, nil
}

func (s *JwksServer) URI() string {
	return s.uri
}

func (s *JwksServer) printJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, err := w.Write(s.jwksBytes)
	if err != nil {
		http.Error(w, "Error writing JWKS", http.StatusInternalServerError)
	}
}
