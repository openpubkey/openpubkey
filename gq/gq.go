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

package gq

import (
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"

	"filippo.io/bigmod"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"golang.org/x/crypto/sha3"
)

var GQ256 = jwa.SignatureAlgorithm("GQ256")

func init() {
	jwa.RegisterSignatureAlgorithm(GQ256)
}

type OptsStruct struct {
	extraClaims map[string]any
}
type Opts func(a *OptsStruct)

// WithExtraClaim specifies additional values to be included in the
// GQ signed JWT. These claims will be included in the protected header
// of the JWT
// Example use:
//
//	WithExtraClaim("claimKey", "claimValue")
func WithExtraClaim(k string, v string) Opts {
	return func(a *OptsStruct) {
		if a.extraClaims == nil {
			a.extraClaims = map[string]any{}
		}
		a.extraClaims[k] = v
	}
}

// GQ256SignJWT takes a rsaPublicKey and signed JWT and computes a GQ1 signature
// on the JWT. It returns a JWT whose RSA signature has been replaced by
// the GQ signature. It is wrapper around SignerVerifier.SignJWT
// an additional check that the correct rsa public key has been supplied.
// Use this instead of SignerVerifier.SignJWT.
func GQ256SignJWT(rsaPublicKey *rsa.PublicKey, jwt []byte, opts ...Opts) ([]byte, error) {
	_, err := jws.Verify(jwt, jws.WithKey(jwa.RS256, rsaPublicKey))
	if err != nil {
		return nil, fmt.Errorf("incorrect public key supplied when GQ signing jwt: %w", err)
	}
	sv, err := New256SignerVerifier(rsaPublicKey)
	if err != nil {
		return nil, fmt.Errorf("error creating GQ signer: %w", err)
	}
	gqJWT, err := sv.SignJWT(jwt, opts...)
	if err != nil {
		return nil, fmt.Errorf("error creating GQ signature: %w", err)
	}
	return gqJWT, nil
}

// GQ256VerifyJWT verifies a GQ1 signature over GQ signed JWT
func GQ256VerifyJWT(rsaPublicKey *rsa.PublicKey, gqToken []byte) (bool, error) {
	sv, err := New256SignerVerifier(rsaPublicKey)
	if err != nil {
		return false, fmt.Errorf("error creating GQ signer: %w", err)
	}
	return sv.VerifyJWT(gqToken), nil
}

// Signer allows for creating GQ1 signatures messages.
type Signer interface {
	// Sign creates a GQ1 signature over the given message with the given GQ1 private number.
	Sign(private []byte, message []byte) ([]byte, error)
	// SignJWT creates a GQ1 signature over the JWT token's header/payload with a GQ1 private number derived from the JWT signature.
	//
	// This works because a GQ1 private number can be calculated as the inverse mod n of an RSA signature, where n is the public RSA modulus.
	SignJWT(jwt []byte, opts ...Opts) ([]byte, error)
}

// Signer allows for verifying GQ1 signatures.
type Verifier interface {
	// Verify verifies a GQ1 signature over a message, using the public identity of the signer.
	Verify(signature []byte, identity []byte, message []byte) bool

	// Compatible with SignJWT, this function verifies the GQ1 signature of the presented JSON Web Token.
	VerifyJWT(jwt []byte) bool
}

// SignerVerifier combines the Signer and Verifier interfaces.
type SignerVerifier interface {
	Signer
	Verifier
}

type signerVerifier struct {
	// n is the RSA public modulus (what Go's RSA lib calls N)
	n *bigmod.Modulus
	// v is the RSA public exponent (what Go's RSA lib calls E)
	v *big.Int
	// nBytes is the length of n in bytes
	nBytes int
	// vBytes is the length of v in bytes
	vBytes int
	// t is the signature length parameter
	t int
}

// Creates a new SignerVerifier specifically for GQ256, meaning the security parameter is 256.
func New256SignerVerifier(publicKey *rsa.PublicKey) (SignerVerifier, error) {
	return NewSignerVerifier(publicKey, 256)
}

// NewSignerVerifier creates a SignerVerifier from the RSA public key of the trusted third-party which creates
// the GQ1 private numbers.
//
// The securityParameter parameter is the level of desired security in bits. 256 is recommended.
func NewSignerVerifier(publicKey *rsa.PublicKey, securityParameter int) (SignerVerifier, error) {
	if publicKey.E != 65537 {
		// Danger: Currently it is unsafe to use this library with a RSA exponent other than 65537.
		// This issue is being tracked in https://github.com/openpubkey/openpubkey/issues/230
		return nil, fmt.Errorf("only 65537 is currently supported, unsupported RSA public key exponent: %d", publicKey.E)
	}
	n, v, nBytes, vBytes, err := parsePublicKey(publicKey)
	t := securityParameter / (vBytes * 8)

	return &signerVerifier{n, v, nBytes, vBytes, t}, err
}

func parsePublicKey(publicKey *rsa.PublicKey) (n *bigmod.Modulus, v *big.Int, nBytes int, vBytes int, err error) {
	n, err = bigmod.NewModulusFromBig(publicKey.N)
	if err != nil {
		return
	}
	v = big.NewInt(int64(publicKey.E))
	nLen := n.BitLen()
	vLen := v.BitLen() - 1 // note the -1; GQ1 only ever uses the (length of v) - 1, so we can just do this here rather than throughout
	nBytes = bytesForBits(nLen)
	vBytes = bytesForBits(vLen)
	return
}

func bytesForBits(bits int) int {
	return (bits + 7) / 8
}

var hash = func(byteCount int, data ...[]byte) ([]byte, error) {
	rng := sha3.NewShake256()
	for _, d := range data {
		rng.Write(d)
	}

	return randomBytes(rng, byteCount)
}

func randomBytes(rng io.Reader, byteCount int) ([]byte, error) {
	bytes := make([]byte, byteCount)

	_, err := io.ReadFull(rng, bytes)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

func OriginalJWTHeaders(jwt []byte) ([]byte, error) {
	token, err := jws.Parse(jwt)
	if err != nil {
		return nil, err
	}

	// a JWT is guaranteed to have exactly one signature
	headers := token.Signatures()[0].ProtectedHeaders()

	if headers.Algorithm() != GQ256 {
		return nil, fmt.Errorf("expected GQ256 alg, got %s", headers.Algorithm())
	}

	origHeaders := []byte(headers.KeyID())
	return origHeaders, nil
}
