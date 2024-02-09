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
	"encoding/json"
	"fmt"
)

type CosignerClaims struct {
	Issuer      string `json:"iss"`
	KeyID       string `json:"kid"`
	Algorithm   string `json:"alg"`
	AuthID      string `json:"eid"`
	AuthTime    int64  `json:"auth_time"`
	IssuedAt    int64  `json:"iat"` // may differ from auth_time because of refresh
	Expiration  int64  `json:"exp"`
	RedirectURI string `json:"ruri"`
	Nonce       string `json:"nonce"`
	Typ         string `json:"typ"`
}

func (p *PKToken) ParseCosignerClaims() (*CosignerClaims, error) {
	protected, err := json.Marshal(p.Cos.ProtectedHeaders())
	if err != nil {
		return nil, err
	}

	var claims CosignerClaims
	if err := json.Unmarshal(protected, &claims); err != nil {
		return nil, err
	}

	// Check that all fields are present
	var missing []string
	if claims.Issuer == "" {
		missing = append(missing, `iss`)
	}
	if claims.KeyID == "" {
		missing = append(missing, `kid`)
	}
	if claims.Algorithm == "" {
		missing = append(missing, `alg`)
	}
	if claims.AuthID == "" {
		missing = append(missing, `eid`)
	}
	if claims.AuthTime == 0 {
		missing = append(missing, `auth_time`)
	}
	if claims.IssuedAt == 0 {
		missing = append(missing, `iat`)
	}
	if claims.Expiration == 0 {
		missing = append(missing, `exp`)
	}
	if claims.RedirectURI == "" {
		missing = append(missing, `ruri`)
	}
	if claims.Nonce == "" {
		missing = append(missing, `nonce`)
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("cosigner protect header missing required headers: %v", missing)
	}

	return &claims, nil
}
