// Copyright 2025 OpenPubkey
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
	"encoding/json"
	"fmt"
	"time"
)

type DpopJwt struct {
	payload       string
	payloadClaims *DpopClaims
	signature     *Signature
	raw           []byte
}

type DpopClaims struct {
	CHash string `json:"c_hash,omitempty"` // Code Hash SHA256 of authorization code (only present in authorization code flow)
	Htm   string `json:"htm"`              // HTTP Method
	Htu   string `json:"htu"`              // HTTP URI
	Iat   int64  `json:"iat"`              // Issued At
	Jti   string `json:"jti"`              // JWT ID
}

func NewDpopJwt(token []byte) (*DpopJwt, error) {
	protected, payload, signature, err := SplitCompact(token)
	if err != nil {
		return nil, err
	}
	dpopJwt := &DpopJwt{
		payload: string(payload),
		signature: &Signature{
			Protected: string(protected),
			Signature: string(signature),
		},
		raw: token,
	}
	if err := ParseJWTSegment(protected, &dpopJwt.signature.protectedClaims); err != nil {
		return nil, fmt.Errorf("error parsing protected: %w", err)
	}
	if err := ParseJWTSegment(payload, &dpopJwt.payloadClaims); err != nil {
		return nil, fmt.Errorf("error parsing payload: %w", err)
	}
	return dpopJwt, nil
}

// GetJWKIfClaimsMatch returns the JWK from the protected header
// of the DPoP JWT if and only if
// 1. the claims in the DPoP match the required claims argument
// 2. and the DPoP JWT IAT is more recent than 60 seconds ago.
func (d *DpopJwt) GetJWKIfClaimsMatch(requiredClaims map[string]any) ([]byte, error) {
	raw := d.signature.protectedClaims.Jwk
	if raw == nil {
		return nil, fmt.Errorf("no jwk in protected header")
	}
	jwkJson, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}

	if _, err := d.payloadClaims.MatchesClaims(requiredClaims); err != nil {
		return nil, fmt.Errorf("DPoP claims do not match expected values: %w", err)
	}

	// Check that the DPoP header is not expired
	if d.payloadClaims.Iat < time.Now().Unix()-60 {
		return nil, fmt.Errorf("DPoP header is expired")
	}

	return jwkJson, nil
}

func (d *DpopJwt) GetClaims() *DpopClaims {
	return d.payloadClaims
}

func (d *DpopJwt) GetPayload() string {
	return d.payload
}

func (d *DpopJwt) GetSignature() *Signature {
	return d.signature
}

func (d *DpopJwt) GetRaw() []byte {
	return d.raw
}

// MatchesClaims compares the DPoP Claims against a map and ensures that for
// each key and value in the map, the DPoP has that claim with the same value.
// Returns true if all claims match. Returns false and error if some claim
// does not match. Note that this does care if a claim is defined in the DPoP
// but not defined in the map.
func (dc *DpopClaims) MatchesClaims(claimsToMatch map[string]any) (bool, error) {

	for key, expectedValue := range claimsToMatch {
		var gotValue any
		switch key {
		case "htu":
			gotValue = dc.Htu
		case "htm":
			gotValue = dc.Htm
		case "iat":
			gotValue = dc.Iat
		case "jti":
			gotValue = dc.Jti
		case "c_hash":
			gotValue = dc.CHash
		default:
			return false, fmt.Errorf("claim %s not found in DPoP", key)
		}

		switch gotType := gotValue.(type) {
		case string:
			if expStr, ok := expectedValue.(string); !ok {
				return false, fmt.Errorf("claim %s in DPoP has wrong type, got %T, want %T", key, expectedValue, expStr)
			} else if gotType != expStr {
				return false, fmt.Errorf("claim %s in DPoP has unexpected value, got %s, want %s", key, gotType, expStr)
			}
		case int64:
			if expInt, ok := expectedValue.(int64); !ok {
				return false, fmt.Errorf("claim %s in DPoP has wrong type, got %T, want %T", key, expectedValue, expInt)
			} else if gotType != expInt {
				return false, fmt.Errorf("claim %s in DPoP has unexpected value, got %d, want %d", key, gotType, expInt)
			}
		default:
			return false, fmt.Errorf("claim %s in DPoP header has unexpected type, got %T", key, gotValue)
		}
	}
	return true, nil
}
