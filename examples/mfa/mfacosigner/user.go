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

package mfacosigner

import (
	"github.com/go-webauthn/webauthn/webauthn"
)

type user struct {
	id          []byte
	username    string
	displayName string
	credentials []webauthn.Credential
}

var _ webauthn.User = (*user)(nil)

func (u *user) WebAuthnID() []byte {
	return u.id
}

func (u *user) WebAuthnName() string {
	return u.username
}

func (u *user) WebAuthnDisplayName() string {
	return u.displayName
}

func (u *user) WebAuthnIcon() string {
	return ""
}

func (u *user) AddCredential(cred webauthn.Credential) {
	u.credentials = append(u.credentials, cred)
}

func (u *user) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}
