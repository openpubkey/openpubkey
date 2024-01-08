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
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jws"
)

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
	if err := protected.Set("alg", cic.PublicKey().Algorithm()); err != nil {
		return nil, err
	}
	if err := protected.Set("kid", pktHash); err != nil {
		return nil, err
	}
	if err := protected.Set("typ", "osm"); err != nil {
		return nil, err
	}

	return jws.Sign(
		content,
		jws.WithKey(
			cic.PublicKey().Algorithm(),
			signer,
			jws.WithProtectedHeaders(protected),
		),
	)
}

func (p *PKToken) VerifySignedMessage(osm []byte) ([]byte, error) {
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

	// Verify typ header matches expected "osm" value
	typ, ok := protected.Get("typ")
	if !ok {
		return nil, fmt.Errorf("missing required header `typ`")
	}
	if typ != "osm" {
		return nil, fmt.Errorf(`incorrect "typ" header, expected "osm" but recieved %s`, typ)
	}

	// Verify key algorithm header matches cic
	if protected.Algorithm() != cic.PublicKey().Algorithm() {
		return nil, fmt.Errorf(`incorrect "alg" header, expected %s but recieved %s`, cic.PublicKey().Algorithm(), protected.Algorithm())
	}

	// Verify kid header matches hash of pktoken
	kid, ok := protected.Get("kid")
	if !ok {
		return nil, fmt.Errorf("missing required header `kid`")
	}

	pktHash, err := p.Hash()
	if err != nil {
		return nil, fmt.Errorf("unable to hash PK Token: %w", err)
	}

	if kid != string(pktHash) {
		return nil, fmt.Errorf(`incorrect "kid" header, expected %s but received %s`, pktHash, kid)
	}

	_, err = jws.Verify(osm, jws.WithKey(cic.PublicKey().Algorithm(), cic.PublicKey()))
	if err != nil {
		return nil, err
	}

	// Return the osm payload
	return message.Payload(), nil
}
