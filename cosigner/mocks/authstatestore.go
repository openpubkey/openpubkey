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

package mocks

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/openpubkey/openpubkey/cosigner"
	"github.com/openpubkey/openpubkey/pktoken"
)

// This is intended for testing purposes. The locking strategy used is not
// particularly efficient. Anyone building a Cosigner should use the interface
// above to replace this in-memory store with a database.
type AuthStateInMemoryStore struct {
	AuthIDIssuer     *cosigner.AuthIDIssuer
	AuthStateMap     map[string]*cosigner.AuthState
	AuthCodeMap      map[string]string
	AuthStateMapLock sync.RWMutex
	AuthcodeMapLock  sync.RWMutex
}

func NewAuthStateInMemoryStore(hmacKey []byte) *AuthStateInMemoryStore {
	return &AuthStateInMemoryStore{
		AuthStateMap:     make(map[string]*cosigner.AuthState),
		AuthCodeMap:      make(map[string]string),
		AuthcodeMapLock:  sync.RWMutex{},
		AuthStateMapLock: sync.RWMutex{},
		AuthIDIssuer:     cosigner.NewAuthIDIssuer(hmacKey),
	}
}

// Writes to the AuthState are not concurrency safe, do not write
func (s *AuthStateInMemoryStore) LookupAuthState(authID string) (*cosigner.AuthState, bool) {
	s.AuthStateMapLock.RLock()
	as, ok := s.AuthStateMap[authID]
	s.AuthStateMapLock.RUnlock()
	return as, ok // Pass by value to prevent writes to the original
}

func (s *AuthStateInMemoryStore) UpdateAuthState(authID string, authState cosigner.AuthState) error {
	s.AuthStateMapLock.Lock()
	defer s.AuthStateMapLock.Unlock()

	if _, ok := s.AuthStateMap[authID]; !ok {
		return fmt.Errorf("failed to upload auth session because authID specified matches no session")
	} else {
		s.AuthStateMap[authID] = &authState
		return nil
	}
}

func (s *AuthStateInMemoryStore) CreateNewAuthSession(pkt *pktoken.PKToken, ruri string, nonce string) (string, error) {
	var claims struct {
		Issuer string `json:"iss"`
		Aud    any    `json:"aud"`
		Sub    string `json:"sub"`
		Email  string `json:"email"`
	}
	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		return "", fmt.Errorf("failed to unmarshal PK Token: %w", err)
	}
	// An audience can be a string or an array of strings.
	//
	// RFC-7519 JSON Web Token (JWT) says:
	// "In the general case, the "aud" value is an array of case-
	// sensitive strings, each containing a StringOrURI value.  In the
	// special case when the JWT has one audience, the "aud" value MAY be a
	// single case-sensitive string containing a StringOrURI value."
	// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
	var audience string
	switch t := claims.Aud.(type) {
	case string:
		audience = t
	case []any:
		audList := []string{}
		for _, v := range t {
			audList = append(audList, v.(string))
		}
		audience = strings.Join(audList, ",")
	default:
		return "", fmt.Errorf("failed to deserialize aud (audience) claim in ID Token: %T", t)
	}

	authState := &cosigner.AuthState{
		Pkt:              pkt,
		Issuer:           claims.Issuer,
		Aud:              audience,
		Sub:              claims.Sub,
		Username:         claims.Email,
		DisplayName:      strings.Split(claims.Email, "@")[0], //TODO: Use full name from ID Token
		RedirectURI:      ruri,
		Nonce:            nonce,
		AuthcodeRedeemed: false,
		AuthcodeIssued:   false,
	}

	if authID, err := s.AuthIDIssuer.CreateAuthID(uint64(time.Now().Unix())); err != nil {
		return "", err
	} else {
		s.AuthStateMapLock.Lock()
		if _, ok := s.AuthStateMap[authID]; ok != false {
			return "", fmt.Errorf("specified authID is already in use")
		}
		s.AuthStateMap[authID] = authState
		s.AuthStateMapLock.Unlock()
		return authID, nil
	}
}

func (s *AuthStateInMemoryStore) CreateAuthcode(authID string) (string, error) {
	authCodeBytes := make([]byte, 32)
	if _, err := rand.Read(authCodeBytes); err != nil {
		return "", err
	}
	authcode := hex.EncodeToString(authCodeBytes)

	// We take a full read write lock here to ensure we don't issue an authcode twice for the same session
	s.AuthStateMapLock.Lock()
	defer s.AuthStateMapLock.Unlock()

	if authState, ok := s.AuthStateMap[authID]; !ok {
		return "", fmt.Errorf("no such authID")
	} else if authState.AuthcodeIssued == true {
		return "", fmt.Errorf("authcode already issued for this authID")
	} else {
		s.AuthcodeMapLock.Lock()
		defer s.AuthcodeMapLock.Unlock()

		if _, ok := s.AuthCodeMap[authcode]; ok {
			return "", fmt.Errorf("authcode collision implies randomness failure in RNG")
		}
		authState.AuthcodeIssued = true
		s.AuthCodeMap[authcode] = authID

		return authcode, nil
	}
}

func (s *AuthStateInMemoryStore) RedeemAuthcode(authcode string) (cosigner.AuthState, string, error) {
	s.AuthcodeMapLock.RLock()
	authID, authcodeFound := s.AuthCodeMap[authcode]
	s.AuthcodeMapLock.RUnlock()
	if !authcodeFound {
		return cosigner.AuthState{}, "", fmt.Errorf("invalid authcode")
	} else {
		s.AuthStateMapLock.Lock()
		defer s.AuthStateMapLock.Unlock()

		authState := s.AuthStateMap[authID]
		if authState.AuthcodeIssued == false {
			// This should never happen
			return cosigner.AuthState{}, "", fmt.Errorf("no authcode issued for this authID")
		}
		if authState.AuthcodeRedeemed == true {
			return cosigner.AuthState{}, "", fmt.Errorf("authcode has already been redeemed")
		}
		authState.AuthcodeRedeemed = true
		return *authState, authID, nil
	}
}
