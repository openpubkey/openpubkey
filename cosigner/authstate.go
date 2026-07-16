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

package cosigner

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken"
)

type AuthState struct {
	Pkt              *pktoken.PKToken
	Issuer           string // ID Token issuer (iss)
	Aud              string // ID Token audience (aud)
	Sub              string // ID Token subject ID (sub)
	Username         string // ID Token email or username
	DisplayName      string // ID Token display name (or username if none given)
	RedirectURI      string // Redirect URI
	Nonce            string // Nonce supplied by user
	AuthcodeIssued   bool   // Has an authcode been issued for this auth session
	AuthcodeRedeemed bool   // Was the pkt cosigned
}

func NewAuthState(pkt *pktoken.PKToken, ruri string, nonce string) (*AuthState, error) {
	var claims oidc.OidcClaims
	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal PK Token: %w", err)
	}

	return &AuthState{
		Pkt:              pkt,
		Issuer:           claims.Issuer,
		Aud:              claims.Audience,
		Sub:              claims.Subject,
		Username:         claims.Email,
		DisplayName:      strings.Split(claims.Email, "@")[0], //TODO: Use full name from ID Token
		RedirectURI:      ruri,
		Nonce:            nonce,
		AuthcodeRedeemed: false,
		AuthcodeIssued:   false,
	}, nil

}

type UserKey struct {
	Issuer string // ID Token issuer (iss)
	Aud    string // ID Token audience (aud)
	Sub    string // ID Token subject ID (sub)
}

func (as AuthState) UserKey() UserKey {
	return UserKey{Issuer: as.Issuer, Aud: as.Aud, Sub: as.Sub}
}
