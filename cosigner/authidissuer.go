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
	"crypto/hmac"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync/atomic"
)

type AuthIDIssuer struct {
	authIdIter atomic.Uint64
	hmacKey    []byte
}

func NewAuthIDIssuer(hmacKey []byte) *AuthIDIssuer {
	return &AuthIDIssuer{
		authIdIter: atomic.Uint64{},
		hmacKey:    hmacKey,
	}
}

func (i *AuthIDIssuer) CreateAuthID(timeNow uint64) (string, error) {
	authIdInt := i.authIdIter.Add(1)
	iterAndTime := []byte{}
	iterAndTime = binary.LittleEndian.AppendUint64(iterAndTime, uint64(authIdInt))
	iterAndTime = binary.LittleEndian.AppendUint64(iterAndTime, timeNow)
	mac := hmac.New(crypto.SHA3_256.New, i.hmacKey)
	if n, err := mac.Write(iterAndTime); err != nil {
		return "", err
	} else if n != 16 {
		return "", fmt.Errorf("unexpected number of bytes read by HMAC, expected 16, got %d", n)
	} else {
		return hex.EncodeToString(mac.Sum(nil)), nil
	}
}
