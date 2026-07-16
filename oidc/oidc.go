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

package oidc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openpubkey/openpubkey/util"
)

type OidcClaims struct {
	Issuer     string              `json:"iss"`
	Subject    string              `json:"sub"`
	Audience   string              `json:"-"`
	Expiration int64               `json:"exp"`
	IssuedAt   int64               `json:"iat"`
	Email      string              `json:"email,omitempty"`
	Nonce      string              `json:"nonce,omitempty"`
	Username   string              `json:"preferred_username,omitempty"`
	FirstName  string              `json:"given_name,omitempty"`
	LastName   string              `json:"family_name,omitempty"`
	Groups     []string            `json:"groups,omitempty"`
	Scopes     []string            `json:"scopes,omitempty"`
	Cnf        *ConfirmationClaims `json:"cnf,omitempty"`
}

// Implement UnmarshalJSON for custom handling during JSON unmarshalling
func (id *OidcClaims) UnmarshalJSON(data []byte) error {
	// unmarshal audience claim separately to account for []string, https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
	type Alias OidcClaims
	aux := &struct {
		Audience any `json:"aud"`
		*Alias
	}{
		Alias: (*Alias)(id),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// An audience can be a string or an array of strings.
	//
	// RFC-7519 JSON Web Token (JWT) says:
	// "In the general case, the "aud" value is an array of case-
	// sensitive strings, each containing a StringOrURI value.  In the
	// special case when the JWT has one audience, the "aud" value MAY be a
	// single case-sensitive string containing a StringOrURI value."
	// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
	switch t := aux.Audience.(type) {
	case string:
		id.Audience = t
	case []any:
		audList := []string{}
		for _, v := range t {
			if audStr, ok := v.(string); ok {
				audList = append(audList, audStr)
			} else {
				return fmt.Errorf("invalid audience type in audience list, got %T", v)
			}
		}
		// TODO: Change audience to []string
		id.Audience = strings.Join(audList, ",")
	case nil:
		id.Audience = ""
	default:
		return fmt.Errorf("invalid audience type, got %T", t)
	}

	return nil
}

// SplitCompact splits a JWT and returns its three parts
// separately: protected headers, payload and signature.
// This is copied from github.com/lestrrat-go/jwx/v2/jws.SplitCompact
// We include it here so so that jwx is not a dependency of simpleJws
func SplitCompact(src []byte) ([]byte, []byte, []byte, error) {
	parts := bytes.Split(src, []byte("."))
	if len(parts) != 3 {
		return nil, nil, nil, fmt.Errorf(`invalid number of segments`)
	}
	return parts[0], parts[1], parts[2], nil
}

func ParseJWTSegment(segment []byte, v any) error {
	segmentJSON, err := util.Base64DecodeForJWT(segment)
	if err != nil {
		return fmt.Errorf("error decoding segment: %w", err)
	}

	err = json.Unmarshal(segmentJSON, v)
	if err != nil {
		return fmt.Errorf("error parsing segment: %w", err)
	}

	return nil
}

type ConfirmationClaims struct {
	Jwk map[string]any `json:"jwk,omitempty"`
}
