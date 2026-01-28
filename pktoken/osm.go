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

package pktoken

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/openpubkey/openpubkey/internal/jwx"
)

// Options configures VerifySignedMessage behavior
type Options struct {
	Typ string // Override for the expected typ value
}

type OptionFunc func(*Options)

// WithTyp sets a custom typ value for verification
func WithTyp(typ string) OptionFunc {
	return func(o *Options) {
		o.Typ = typ
	}
}

// NewSignedMessage signs a message with the signer provided. The signed
// message is OSM (OpenPubkey Signed Message) which is a type of
// JWS (JSON Web Signature). OSMs commit to the PK Token which was used
// to generate the OSM.
func (p *PKToken) NewSignedMessage(content []byte, signer crypto.Signer) ([]byte, error) {
	cic, err := p.GetCicValues()
	if err != nil {
		return nil, err
	}

	pktHash, err := p.Hash()
	if err != nil {
		return nil, err
	}

	// Create our headers as defined by section 3.5 of the OpenPubkey paper
	protected := jws.NewHeaders()
	if err := protected.Set("alg", cic.KeyAlgorithm()); err != nil {
		return nil, err
	}
	if err := protected.Set("kid", pktHash); err != nil {
		return nil, err
	}
	if err := protected.Set("typ", "osm"); err != nil {
		return nil, err
	}

	jwaAlg, ok := jwx.FromJoseAlgorithm(cic.KeyAlgorithm())
	if !ok {
		return nil, errors.New("invalid algorithm")
	}

	return jws.Sign(
		content,
		jws.WithKey(jwaAlg, signer, jws.WithProtectedHeaders(protected)),
	)
}

// VerifySignedMessage verifies that an OSM (OpenPubkey Signed Message) using
// the public key in this PK Token. If verification is successful,
// VerifySignedMessage returns the content of the signed message. Otherwise
// it returns an error explaining why verification failed.
//
// Note: VerifySignedMessage does not check this the PK Token is valid.
// The PK Token should always be verified first before calling
// VerifySignedMessage
func (p *PKToken) VerifySignedMessage(osm []byte, options ...OptionFunc) ([]byte, error) {
	// Default options
	opts := Options{
		Typ: "osm", // Default to "osm" for backward compatibility
	}
	// Apply provided options
	for _, opt := range options {
		opt(&opts)
	}

	cic, err := p.GetCicValues()
	if err != nil {
		return nil, err
	}

	message, err := jws.Parse(osm)
	if err != nil {
		return nil, err
	}

	// Check that our OSM headers are correct
	if len(message.Signatures()) != 1 {
		return nil, fmt.Errorf("expected only one signature on jwt, received %d", len(message.Signatures()))
	}
	protected := message.Signatures()[0].ProtectedHeaders()

	// Verify typ header matches expected value from options
	var typ string
	err = protected.Get("typ", &typ)
	if err != nil {
		return nil, fmt.Errorf("missing required header `typ`: %w", err)
	}
	if typ != opts.Typ {
		return nil, fmt.Errorf(`incorrect "typ" header, expected %q but received %s`, opts.Typ, typ)
	}

	// Verify key algorithm header matches cic
	protectedAlg, ok := protected.Algorithm()
	if !ok {
		return nil, fmt.Errorf("missing algorithm header")
	}
	jwkKey, err := jwk.Import(cic.PublicKey())
	if err != nil {
		return nil, err
	}
	jwaAlg, ok := jwx.FromJoseAlgorithm(cic.KeyAlgorithm())
	if !ok {
		return nil, fmt.Errorf("unsupported key algorithm: %s", cic.KeyAlgorithm())
	}
	if err := jwkKey.Set(jwk.AlgorithmKey, jwaAlg); err != nil {
		return nil, fmt.Errorf("failed to set algorithm on JWK: %w", err)
	}
	if protectedAlg != jwaAlg {
		return nil, fmt.Errorf(`incorrect "alg" header, expected %s but received %s`, jwaAlg.String(), protectedAlg.String())
	}

	// Verify kid header matches hash of pktoken
	var kid string
	err = protected.Get("kid", &kid)
	if err != nil {
		return nil, fmt.Errorf("missing required header `kid`: %w", err)
	}

	pktHash, err := p.Hash()
	if err != nil {
		return nil, fmt.Errorf("unable to hash PK Token: %w", err)
	}

	if kid != string(pktHash) {
		return nil, fmt.Errorf(`incorrect "kid" header, expected %s but received %s`, pktHash, kid)
	}

	_, err = jws.Verify(osm, jws.WithKey(jwaAlg, jwkKey))
	if err != nil {
		return nil, err
	}

	// Return the osm payload
	return message.Payload(), nil
}
