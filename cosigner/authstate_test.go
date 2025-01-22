// Copyright 2025 OpenPubkey
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

package cosigner_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/cosigner"
	"github.com/openpubkey/openpubkey/pktoken/mocks"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestAuthState(t *testing.T) {
	// Generate the key pair for our cosigner
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	require.NoError(t, err, "failed to generate key pair")

	pkt, err := mocks.GenerateMockPKToken(t, signer, alg)
	require.NoError(t, err)

	ruri := "http://example.com/redirect"
	nonce := "test-nonce"
	authState, err := cosigner.NewAuthState(pkt, ruri, nonce)
	require.NoError(t, err, "failed to create auth state")
	require.NotNil(t, authState, "auth state is nil")

	require.Equal(t, ruri, authState.RedirectURI, "redirect uri mismatch")

	userKey := authState.UserKey()
	require.NotNil(t, userKey, "user key is nil")
	require.Equal(t, "mockIssuer", userKey.Issuer, "issuer mismatch")
	require.Equal(t, "empty", userKey.Aud, "aud mismatch")
	require.Equal(t, "me", userKey.Sub, "issuer mismatch")
}
