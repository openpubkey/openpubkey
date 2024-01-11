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
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"

	"github.com/openpubkey/openpubkey/util"

	_ "golang.org/x/crypto/sha3"
)

type SignatureType string

const (
	OIDC SignatureType = "JWT"
	CIC  SignatureType = "CIC"
	COS  SignatureType = "COS"
)

type Signature = jws.Signature

type PKToken struct {
	raw []byte // the original, raw representation of the object

	Payload []byte     // decoded payload
	Op      *Signature // Provider Signature
	Cic     *Signature // Client Signature
	Cos     *Signature // Cosigner Signature
}

// kid isn't always present, and is only guaranteed to be unique within a given key set,
// so we can use the thumbprint of the key instead to identify it at verification time
func (p *PKToken) AddJKTHeader(opKey crypto.PublicKey) error {
	public, err := jwk.FromRaw(opKey)
	if err != nil {
		return fmt.Errorf("failed to create JWK from public key: %w", err)
	}
	thumbprint, err := public.Thumbprint(crypto.SHA256)
	if err != nil {
		return fmt.Errorf("failed to calculate thumbprint: %w", err)
	}
	headers := p.Op.PublicHeaders()
	if headers == nil {
		headers = jws.NewHeaders()
	}
	err = headers.Set("jkt", util.Base64EncodeForJWT(thumbprint))
	if err != nil {
		return fmt.Errorf("failed to set jkt claim: %w", err)
	}
	p.Op.SetPublicHeaders(headers)
	return nil
}

func New(idToken []byte, cicToken []byte) (*PKToken, error) {
	pkt := &PKToken{}

	if err := pkt.AddSignature(idToken, OIDC); err != nil {
		return nil, err
	}

	if err := pkt.AddSignature(cicToken, CIC); err != nil {
		return nil, err
	}

	return pkt, nil
}

// Signs PK Token and then returns only the payload, header and signature as a JWT
func (p *PKToken) SignToken(
	signer crypto.Signer,
	alg jwa.KeyAlgorithm,
	protected map[string]any,
) ([]byte, error) {
	headers := jws.NewHeaders()
	for key, val := range protected {
		if err := headers.Set(key, val); err != nil {
			return nil, fmt.Errorf("malformatted headers: %w", err)
		}
	}
	return jws.Sign(
		p.Payload,
		jws.WithKey(
			alg,
			signer,
			jws.WithProtectedHeaders(headers),
		),
	)
}

func (p *PKToken) Sign(
	sigType SignatureType,
	signer crypto.Signer,
	alg jwa.KeyAlgorithm,
	protected map[string]any,
) error {
	token, err := p.SignToken(signer, alg, protected)
	if err != nil {
		return err
	}
	return p.AddSignature(token, sigType)
}

func (p *PKToken) AddSignature(token []byte, sigType SignatureType) error {
	message, err := jws.Parse(token)
	if err != nil {
		return err
	}

	// If there is no payload, we set the provided token's payload as current, otherwise
	// we make sure that the new payload matches current
	if p.Payload == nil {
		p.Payload = message.Payload()
	} else if !bytes.Equal(p.Payload, message.Payload()) {
		return fmt.Errorf("payload in the GQ token (%s) does not match the existing payload in the PK Token (%s)", p.Payload, message.Payload())
	}

	signature := message.Signatures()[0]

	if sigType == CIC || sigType == COS {
		protected := signature.ProtectedHeaders()
		if sigTypeFound, ok := protected.Get(jws.TypeKey); !ok {
			return fmt.Errorf("required 'typ' claim not found in protected")
		} else if sigTypeFoundStr, ok := sigTypeFound.(string); !ok {
			return fmt.Errorf("'typ' claim in protected must be a string but was a %T", sigTypeFound)
		} else if sigTypeFoundStr != string(sigType) {
			return fmt.Errorf("incorrect 'typ' claim in protected, expected (%s), got (%s)", sigType, sigTypeFound)
		}
	}

	switch sigType {
	case OIDC:
		p.Op = signature
	case CIC:
		p.Cic = signature
	case COS:
		p.Cos = signature
	default:
		return fmt.Errorf("unrecognized signature type: %s", string(sigType))
	}
	return nil
}

func (p *PKToken) ProviderAlgorithm() (jwa.SignatureAlgorithm, bool) {
	alg, ok := p.Op.ProtectedHeaders().Get(jws.AlgorithmKey)
	if !ok {
		return "", false
	}

	return alg.(jwa.SignatureAlgorithm), true
}

func (p *PKToken) Compact(sig *Signature) ([]byte, error) {
	message := jws.NewMessage().
		SetPayload(p.Payload).
		AppendSignature(sig)
	return jws.Compact(message)
}

func (p *PKToken) Hash() (string, error) {
	/*
		We set the raw variable when unmarshaling from json (the only current string representation of a
		PK Token) so when we hash we use the same representation that was given for consistency. When the
		token being hashed is a new PK Token, we marshal it ourselves. This can introduce some issues based
		on how different languages format their json strings.
	*/
	message := p.raw
	var err error
	if message == nil {
		message, err = json.Marshal(p)
		if err != nil {
			return "", err
		}
	}

	hash := util.B64SHA3_256(message)
	return string(hash), nil
}

func (p *PKToken) MarshalJSON() ([]byte, error) {
	message := jws.NewMessage().
		SetPayload(p.Payload).
		AppendSignature(p.Op).
		AppendSignature(p.Cic)

	if p.Cos != nil {
		message.AppendSignature(p.Cos)
	}

	return json.Marshal(message)
}

func (p *PKToken) UnmarshalJSON(data []byte) error {
	var parsed jws.Message
	if err := json.Unmarshal(data, &parsed); err != nil {
		return err
	}

	p.Payload = parsed.Payload() // base64 decoded

	opCount := 0
	cicCount := 0
	cosCount := 0
	for _, signature := range parsed.Signatures() {
		// for some reason the unmarshaled signatures have empty non-nil
		// public headers. set them to nil instead.
		public := signature.PublicHeaders()
		pubMap, _ := public.AsMap(context.Background())
		if len(pubMap) == 0 {
			signature.SetPublicHeaders(nil)
		}

		protected := signature.ProtectedHeaders()
		var sigType SignatureType

		typeHeader, ok := protected.Get(jws.TypeKey)
		if ok {
			sigTypeStr, ok := typeHeader.(string)
			if !ok {
				return fmt.Errorf(`provided "%s" is of wrong type, expected string`, jws.TypeKey)
			}

			sigType = SignatureType(sigTypeStr)
		} else {
			// missing typ claim, assuming this is from the OIDC provider
			sigType = OIDC
		}

		switch sigType {
		case OIDC:
			opCount += 1
			p.Op = signature
		case CIC:
			cicCount += 1
			p.Cic = signature
		case COS:
			cosCount += 1
			p.Cos = signature
		default:
			return fmt.Errorf("unrecognized signature type: %s", sigType)
		}
	}

	// Do some signature count verifications
	if opCount == 0 {
		return fmt.Errorf(`at least one signature of type "oidc" or "oidc_gq" is required`)
	} else if opCount > 1 {
		return fmt.Errorf(`only one signature of type "oidc" or "oidc_gq" is allowed, found %d`, opCount)
	}

	if cicCount == 0 {
		return fmt.Errorf(`at least one signature of type "cic" is required`)
	} else if cicCount > 1 {
		return fmt.Errorf(`only one signature of type "cic" is allowed, found %d`, cicCount)
	}

	if cosCount > 1 {
		return fmt.Errorf(`only one signature of type "cos" is allowed, found %d`, cosCount)
	}

	return nil
}
