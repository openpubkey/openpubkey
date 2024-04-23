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

package discover

import (
	"context"
	"crypto"
	"encoding/json"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func MockGetJwksByIssuer(publicKeys []crypto.PublicKey, keyIDs []string, algs []string) (JwksFetchFunc, error) {
	// Create JWKS (JWK Set)
	jwks := jwk.NewSet()

	for i, publicKey := range publicKeys {
		jwkKey, err := jwk.PublicKeyOf(publicKey)
		if err != nil {
			return nil, err
		}

		if err := jwkKey.Set(jwk.AlgorithmKey, algs[i]); err != nil {
			return nil, err
		}

		if keyIDs != nil {
			if err := jwkKey.Set(jwk.KeyIDKey, keyIDs[i]); err != nil {
				return nil, err
			}
		}

		// Put our jwk into a set
		if err := jwks.AddKey(jwkKey); err != nil {
			return nil, err
		}
	}

	jwksJson, err := json.Marshal(jwks)
	if err != nil {
		return nil, err
	}

	return func(ctx context.Context, issuer string) ([]byte, error) {
		return jwksJson, nil
	}, nil
}

func MockGetJwksByIssuerOneKey(publicKey crypto.PublicKey, keyID string, alg string) (JwksFetchFunc, error) {
	// Create JWKS (JWK Set)
	jwkKey, err := jwk.PublicKeyOf(publicKey)
	if err != nil {
		return nil, err
	}

	if err := jwkKey.Set(jwk.AlgorithmKey, alg); err != nil {
		return nil, err
	}
	if err := jwkKey.Set(jwk.KeyIDKey, keyID); err != nil {
		return nil, err
	}

	// Put our jwk into a set
	jwks := jwk.NewSet()
	if err := jwks.AddKey(jwkKey); err != nil {
		return nil, err
	}

	jwksJson, err := json.Marshal(jwks)
	if err != nil {
		return nil, err
	}

	return func(ctx context.Context, issuer string) ([]byte, error) {
		return jwksJson, nil
	}, nil
}
