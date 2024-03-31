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

package backend

import (
	"crypto"
	"encoding/json"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
)

type CommitmentType struct {
	ClaimCommitment bool
	ClaimName       string
}

type IDTokenTemplate struct {
	CommitmentFunc       func(*IDTokenTemplate, string)
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

// AddCommit adds the commitment to the CIC to the ID Token. The
// CommitmentFunc is specifed allowing custom commitment functions to be specified
func (t *IDTokenTemplate) AddCommit(cicHash string) {
	t.CommitmentFunc(t, cicHash)
}

// TODO: rename t as it is confusing with t being used in tests

func (t *IDTokenTemplate) IssueToken() ([]byte, error) {

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

func AddNonceCommit(idtTemp *IDTokenTemplate, cicHash string) {
	idtTemp.Nonce = cicHash
	idtTemp.NoNonce = false
}

func AddAudCommit(idtTemp *IDTokenTemplate, cicHash string) {
	idtTemp.Aud = cicHash
}

func NoClaimCommit(idtTemp *IDTokenTemplate, cicHash string) {
	// Do nothing
}
