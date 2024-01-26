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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/util"
	oidcclient "github.com/zitadel/oidc/v2/pkg/client"
)

type CosignerClaims struct {
	Iss         string `json:"iss"`
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

func ParseCosignerClaims(protected []byte) (*CosignerClaims, error) {
	var claims CosignerClaims
	if err := json.Unmarshal(protected, &claims); err != nil {
		return nil, err
	}

	// Check that all fields are present
	var missing []string
	if claims.Iss == "" {
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

func (p *PKToken) VerifyCosSig() error {
	if p.Cos == nil {
		return fmt.Errorf("no cosigner signature")
	}

	cosToken, err := p.Compact(p.Cos)
	if err != nil {
		return err
	}

	// Parse our header
	rawHeader, _, _, err := jws.SplitCompact(cosToken)
	if err != nil {
		return err
	}
	decodedHeader, err := util.Base64DecodeForJWT(rawHeader)
	if err != nil {
		return err
	}
	header, err := ParseCosignerClaims(decodedHeader)
	if err != nil {
		return err
	}

	// Check if it's expired
	if time.Now().After(time.Unix(header.Expiration, 0)) {
		return fmt.Errorf("cosigner signature expired")
	}

	discConf, err := oidcclient.Discover(header.Iss, http.DefaultClient)
	if err != nil {
		return fmt.Errorf("failed to call OIDC discovery endpoint: %w", err)
	}
	set, err := jwk.Fetch(context.Background(), discConf.JwksURI)
	if err != nil {
		return fmt.Errorf("failed to fetch public keys from Cosigner JWKS endpoint: %w", err)
	}

	key, ok := set.LookupKeyID(header.KeyID)
	if !ok {
		return fmt.Errorf("missing key id (kid)")
	}

	if header.Algorithm != key.Algorithm().String() {
		return fmt.Errorf("key (kid=%s) has alg (%s) which doesn't match alg (%s) in protected", key.KeyID(), key.Algorithm(), header.Algorithm)
	}

	_, err = jws.Verify(cosToken, jws.WithKey(jwa.KeyAlgorithmFrom(key.Algorithm()), key))

	return err
}
