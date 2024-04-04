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
	"fmt"
)

type Jwt struct {
	payload       string
	payloadClaims *OidcClaims
	signature     *Signature
	raw           []byte
}

func NewJwt(token []byte) (*Jwt, error) {
	protected, payload, signature, err := SplitCompact(token)
	if err != nil {
		return nil, err
	}
	idt := &Jwt{
		payload: string(payload),
		signature: &Signature{
			Protected: string(protected),
			Signature: string(signature),
		},
		raw: token,
	}
	if err := ParseJWTSegment(protected, &idt.signature.protectedClaims); err != nil {
		return nil, fmt.Errorf("error parsing protected: %w", err)
	}
	if err := ParseJWTSegment(payload, &idt.payloadClaims); err != nil {
		return nil, fmt.Errorf("error parsing payload: %w", err)
	}
	return idt, nil
}

func (i *Jwt) GetClaims() *OidcClaims {
	return i.payloadClaims
}

func (i *Jwt) GetPayload() string {
	return i.payload
}

func (i *Jwt) GetSignature() *Signature {
	return i.signature
}

func (i *Jwt) GetRaw() []byte {
	return i.raw
}
