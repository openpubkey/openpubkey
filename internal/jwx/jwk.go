// Copyright 2026 OpenPubkey
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

package jwx

import (
	"crypto"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// JwkThumbprint computes the RFC 7638 SHA-256 JWK thumbprint of the JWK
// provided as a map. Non-required members (e.g. alg) are ignored per RFC 7638,
// so two representations of the same key produce the same thumbprint
// even if the bytes differ.
func JwkThumbprint(jwkMap map[string]any) ([]byte, error) {
	if len(jwkMap) == 0 {
		return nil, fmt.Errorf("jwk is empty")
	}
	jwkBytes, err := json.Marshal(jwkMap)
	if err != nil {
		return nil, fmt.Errorf("error marshalling jwk: %w", err)
	}
	key, err := jwk.ParseKey(jwkBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing jwk: %w", err)
	}
	return key.Thumbprint(crypto.SHA256)
}
