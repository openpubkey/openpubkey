// Copyright 2025 OpenPubkey
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

package mocks

import (
	"crypto"
	"encoding/json"
	"fmt"
	mathrand "math/rand"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/discover"
	"golang.org/x/exp/maps"
)

type Issuer struct {
	Issuer                string
	ProviderSigningKeySet map[string]crypto.Signer            // kid (keyId) -> signing key
	ProviderPublicKeySet  map[string]discover.PublicKeyRecord // kid (keyId) -> PublicKeyRecord
	// IDTokensTemplate      *IDTokenTemplate
}

func NewIssuer(issuer string, alg string, numKeys int) (*Issuer, error) {
	var providerSigningKeySet map[string]crypto.Signer
	var providerPublicKeySet map[string]discover.PublicKeyRecord
	var err error

	switch alg {
	case "RS256":
		if providerSigningKeySet, providerPublicKeySet, err = CreateRS256KeySet(issuer, numKeys); err != nil {
			return nil, err
		}
	case "ES256":
		if providerSigningKeySet, providerPublicKeySet, err = CreateES256KeySet(issuer, numKeys); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported provider alg: %s", alg)
	}

	return &Issuer{
		Issuer:                issuer,
		ProviderSigningKeySet: providerSigningKeySet,
		ProviderPublicKeySet:  providerPublicKeySet,
	}, nil
}

// func (o *MockProviderBackend) SetIDTokenTemplate(template *IDTokenTemplate) {
// 	o.IDTokensTemplate = template
// }

func (i *Issuer) RandomSigningKey() (crypto.Signer, string, discover.PublicKeyRecord) {
	keyIDs := maps.Keys(i.ProviderPublicKeySet)
	keyID := keyIDs[mathrand.Intn(len(keyIDs))]
	return i.ProviderSigningKeySet[keyID], keyID, i.ProviderPublicKeySet[keyID]
}

func (i *Issuer) GetJwks() ([]byte, error) {
	keySet := jwk.NewSet()
	for kid, v := range i.ProviderPublicKeySet {
		jwkKey, err := jwk.PublicKeyOf(v.PublicKey)
		if err != nil {
			return nil, err
		}
		if err := jwkKey.Set(jwk.AlgorithmKey, v.Alg); err != nil {
			return nil, err
		}
		if err := jwkKey.Set(jwk.KeyIDKey, kid); err != nil {
			return nil, err
		}
		if err := keySet.AddKey(jwkKey); err != nil {
			return nil, err
		}
	}
	return json.Marshal(keySet)
}

func (i *Issuer) SignJwt(payloadBytes []byte, protected map[string]any) ([]byte, error) {
	signer, kid, pkr := i.RandomSigningKey()

	headers := jws.NewHeaders()
	if err := headers.Set(jws.AlgorithmKey, pkr.Alg); err != nil {
		return nil, err
	}
	if err := headers.Set(jws.KeyIDKey, kid); err != nil {
		return nil, err
	}
	if err := headers.Set(jws.TypeKey, "JWT"); err != nil {
		return nil, err
	}

	for k, v := range protected {
		if err := headers.Set(k, v); err != nil {
			return nil, err
		}
	}

	return jws.Sign(
		payloadBytes,
		jws.WithKey(
			jwa.KeyAlgorithmFrom(pkr.Alg),
			signer,
			jws.WithProtectedHeaders(headers),
		),
	)
}

//TODO: Figure out how to merge this with ID Token template
