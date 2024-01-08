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
	"crypto"
	"encoding/json"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/pktoken"
)

type Cosigner struct {
	Alg    jwa.KeyAlgorithm
	Signer crypto.Signer
}

func (c *Cosigner) Cosign(pkt *pktoken.PKToken, cosClaims pktoken.CosignerClaims) ([]byte, error) {
	jsonBytes, err := json.Marshal(cosClaims)
	if err != nil {
		return nil, err
	}
	var headers map[string]any
	if err := json.Unmarshal(jsonBytes, &headers); err != nil {
		return nil, err
	}
	return pkt.SignToken(c.Signer, c.Alg, headers)
}
