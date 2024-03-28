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

package override

import (
	"crypto"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
)

type CommitmentType struct {
	ClaimCommitment bool
	ClaimName       string
}

type IDTokenTemplate struct {
	CommitmentType       *CommitmentType
	Issuer               string
	Nonce                string
	NoNonce              bool
	Aud                  string
	KeyID                string
	NoKeyID              bool
	Alg                  string
	NoAlg                bool // Even if NOAlg is true, we still need Alg to be set to generate the signature
	ExtraClaims          map[string]any
	ExtraProtectedClaims map[string]any
	SigningKey           crypto.Signer // The key we will use to sign the ID Token

}

func (t *IDTokenTemplate) Issue(cicHash string) ([]byte, error) {

	headers := jws.NewHeaders()
	if !t.NoAlg {
		headers.Set(jws.AlgorithmKey, t.Alg)
	}
	if !t.NoKeyID {
		headers.Set(jws.KeyIDKey, t.KeyID)
	}
	headers.Set(jws.TypeKey, "JWT")

	if t.ExtraProtectedClaims != nil {
		for k, v := range t.ExtraProtectedClaims {
			headers.Set(k, v)
		}
	}

	payloadMap := map[string]any{
		"sub": "me",
		"aud": t.Aud,
		"iss": t.Issuer,
		"iat": time.Now().Unix(),
	}

	if !t.NoNonce {
		payloadMap["nonce"] = t.Nonce
	}

	if t.ExtraClaims != nil {
		for k, v := range t.ExtraClaims {
			payloadMap[k] = v
		}
	}

	// Set the CIC Commitment in the ID Token
	if t.CommitmentType == nil {
		return nil, fmt.Errorf("CommitmentType can't be nil")
	}
	if t.CommitmentType.ClaimCommitment {
		if t.CommitmentType.ClaimName == "" {
			return nil, fmt.Errorf("ClaimName can't be empty")
		}
		payloadMap[t.CommitmentType.ClaimName] = cicHash
	}

	payloadBytes, err := json.Marshal(payloadMap)
	if err != nil {
		return nil, err
	}

	return jws.Sign(
		payloadBytes,
		jws.WithKey(
			jwa.KeyAlgorithmFrom(t.Alg),
			t.SigningKey,
			jws.WithProtectedHeaders(headers),
		),
	)
}