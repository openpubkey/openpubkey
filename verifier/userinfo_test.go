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

package verifier_test

import (
	"context"
	"testing"

	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/providers/mocks"
	"github.com/openpubkey/openpubkey/verifier"
	"github.com/stretchr/testify/require"
)

const userInfoResponse = `{
	"sub": "me",
	"email": "alice@example.com",
	"name": "Alice Example"
}`

func TestGoogleSimpleRequest(t *testing.T) {
	issuer := "https://accounts.google.com"
	clientID := "verifier"

	noGQSign := false
	provider, _, err := NewMockOpenIdProvider(noGQSign, issuer, "RS256", clientID, map[string]any{
		"aud": clientID,
	})
	require.NoError(t, err)
	opkClient, err := client.New(provider)
	require.NoError(t, err)
	pkt, err := opkClient.Auth(context.Background())
	require.NoError(t, err)

	accessToken := opkClient.GetAccessToken()
	require.NotEmpty(t, accessToken)

	require.Equal(t, "mock-access-token", string(accessToken))

	uiRequester, err := verifier.NewUserInfoRequester(pkt, string(accessToken))
	require.NoError(t, err)

	uiRequester.HttpClient = mocks.NewMockGoogleUserInfoHTTPClient(userInfoResponse)
	userInfoJson, err := uiRequester.Request(context.Background())
	require.NoError(t, err)

	require.Contains(t, userInfoJson, `"email":"alice@example.com"`)
	require.Contains(t, userInfoJson, `"sub":"me"`)
}
