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

package clientinstance

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/openpubkey/openpubkey/internal/jwx"
	"github.com/openpubkey/openpubkey/jose"
	"github.com/openpubkey/openpubkey/util"
)

// Client Instance Claims, referred also as "cic" in the OpenPubKey paper
type Claims struct {
	publicKey crypto.PublicKey
	algorithm string

	// Claims are stored in the protected header portion of JWS signature
	protected map[string]any
}

// Client instance claims must relate to a single key pair
func NewClaims(publicKey crypto.PublicKey, claims map[string]any) (*Claims, error) {
	jwkKey, err := jwk.PublicKeyOf(publicKey)
	if err != nil {
		return nil, err
	}

	// Make sure no claims are using our reserved values
	for _, reserved := range []string{"alg", "upk", "rz", "typ"} {
		if _, ok := claims[reserved]; ok {
			return nil, fmt.Errorf("use of reserved header name, %s, in additional headers", reserved)
		}
	}

	rand, err := generateRand()
	if err != nil {
		return nil, fmt.Errorf("failed to generate random value: %w", err)
	}

	alg, ok := jwkKey.Algorithm()
	if !ok {
		return nil, fmt.Errorf("failed to get algorithm from jwk key")
	}

	// Assign required values
	claims["typ"] = "CIC"
	claims["alg"] = alg
	claims["upk"] = jwkKey
	claims["rz"] = rand

	return &Claims{
		publicKey: publicKey,
		algorithm: alg.String(),
		protected: claims,
	}, nil
}

func ParseClaims(protected map[string]any) (*Claims, error) {
	// Get our standard headers and make sure they match up
	if _, ok := protected["rz"]; !ok {
		return nil, fmt.Errorf(`missing required "rz" claim`)
	}
	upk, ok := protected["upk"]
	if !ok {
		return nil, fmt.Errorf(`missing required "upk" claim`)
	}
	upkBytes, err := json.Marshal(upk)
	if err != nil {
		return nil, err
	}
	upkjwk, err := jwk.ParseKey(upkBytes)
	if err != nil {
		return nil, err
	}
	alg, ok := protected["alg"]
	if !ok {
		return nil, fmt.Errorf(`missing required "alg" claim`)
	}
	upkAlg, ok := upkjwk.Algorithm()
	if !ok {
		return nil, fmt.Errorf(`failed to get algorithm from jwk key`)
	}
	if alg != upkAlg {
		return nil, fmt.Errorf(`provided "alg" value different from algorithm provided in "upk" jwk`)
	}
	// Export to any first, then convert to the appropriate concrete type
	// This is necessary because jwk.Export needs to know the concrete type
	var pubKeyAny any
	if err := jwk.Export(upkjwk, &pubKeyAny); err != nil {
		return nil, fmt.Errorf("failed to extract public key from JWK: %w", err)
	}

	// If we got a private key (crypto.Signer), extract its public key
	if signer, ok := pubKeyAny.(crypto.Signer); ok {
		pubKeyAny = signer.Public()
	}

	var pubKey crypto.PublicKey
	// Validate that key type matches the declared algorithm
	switch upkAlg {
	case jwa.RS256():
		rsaKey, ok := pubKeyAny.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("algorithm %s requires RSA key, got %T", upkAlg, pubKeyAny)
		}
		pubKey = rsaKey
	case jwa.ES256():
		ecdsaKey, ok := pubKeyAny.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("algorithm %s requires ECDSA key, got %T", upkAlg, pubKeyAny)
		}
		pubKey = ecdsaKey
	case jwa.EdDSA():
		edKey, ok := pubKeyAny.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("algorithm %s requires Ed25519 key, got %T", upkAlg, pubKeyAny)
		}
		pubKey = edKey
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", upkAlg)
	}

	return &Claims{
		publicKey: pubKey,
		algorithm: upkAlg.String(),
		protected: protected,
	}, nil
}

func (c *Claims) PublicKey() crypto.PublicKey {
	return c.publicKey
}

func (c *Claims) KeyAlgorithm() jose.KeyAlgorithm {
	return jose.KeyAlgorithm(c.algorithm)
}

// Returns a hash of all client instance claims which includes a random value
func (c *Claims) Hash() ([]byte, error) {
	buf, err := json.Marshal(c.protected)
	if err != nil {
		return nil, err
	}

	return util.B64SHA3_256(buf), nil
}

// This function signs the payload of the provided token with the protected headers
// as defined by the client instance claims and returns a jwt in compact form.
func (c *Claims) Sign(signer crypto.Signer, algorithm jose.KeyAlgorithm, token []byte) ([]byte, error) {
	_, payload, _, err := jws.SplitCompact(token)
	if err != nil {
		return nil, err
	}

	// We need to make sure we're signing the decoded bytes
	payloadDecoded, err := util.Base64DecodeForJWT(payload)
	if err != nil {
		return nil, err
	}

	headers := jws.NewHeaders()
	for key, val := range c.protected {
		if err := headers.Set(key, val); err != nil {
			return nil, err
		}
	}

	jwxAlg, ok := jwx.FromJoseAlgorithm(algorithm)
	if !ok {
		return nil, fmt.Errorf("unsupported key algorithm: %s", algorithm)
	}

	cicToken, err := jws.Sign(
		payloadDecoded,
		jws.WithKey(
			jwxAlg,
			signer,
			jws.WithProtectedHeaders(headers),
		),
	)
	if err != nil {
		return nil, err
	}

	return cicToken, nil
}

func generateRand() (string, error) {
	bits := 256
	rBytes := make([]byte, bits/8)
	_, err := rand.Read(rBytes)
	if err != nil {
		return "", err
	}

	rz := hex.EncodeToString(rBytes)
	return rz, nil
}
