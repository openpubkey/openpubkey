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
	"errors"
	"testing"

	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/providers/mocks"
	"github.com/openpubkey/openpubkey/verifier"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v4/pkg/client/rp"
)

const userInfoResponse = `{
	"sub": "me",
	"email": "alice@example.com",
	"name": "Alice Example",
	"groups": ["group1", "group2"]
}`

func TestGoogleSimpleRequest(t *testing.T) {
	issuer := "https://accounts.google.com"
	clientID := "verifier"
	expectedAccessToken := "mock-access-token"

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

	require.Equal(t, expectedAccessToken, string(accessToken))

	uiRequester, err := verifier.NewUserInfoRequester(pkt, string(accessToken))
	require.NoError(t, err)

	uiRequester.HttpClient = mocks.NewMockGoogleUserInfoHTTPClient(userInfoResponse, expectedAccessToken)
	userInfoJson, err := uiRequester.Request(context.Background())
	require.NoError(t, err)

	require.Contains(t, userInfoJson, `"email":"alice@example.com"`)
	require.Contains(t, userInfoJson, `"sub":"me"`)

	uiRequester.HttpClient = mocks.NewMockGoogleUserInfoHTTPClient(userInfoResponse, "Invalid-Access-Token")
	userInfoJson, err = uiRequester.Request(context.Background())
	require.Error(t, err)
	require.Empty(t, userInfoJson)

	uiRequester.HttpClient = mocks.NewMockBrokenHTTPClient(userInfoResponse, expectedAccessToken, errors.New("failed to connect"))
	userInfoJson, err = uiRequester.Request(context.Background())
	require.Error(t, err)
	require.Empty(t, userInfoJson)
	require.Contains(t, err.Error(), "failed to connect")

	uiRequester.HttpClient = mocks.NewMockGoogleUserInfoHTTPClientCorruptedJson(userInfoResponse, expectedAccessToken)
	userInfoJson, err = uiRequester.Request(context.Background())
	require.Error(t, err)
	require.Empty(t, userInfoJson)
	require.Contains(t, err.Error(), "failed to unmarshal response: invalid character")
}

func TestGCorruptedPKTokenUserinfoRequest(t *testing.T) {
	issuer := "https://accounts.google.com"
	clientID := "verifier"
	expectedAccessToken := "mock-access-token"

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

	require.Equal(t, expectedAccessToken, string(accessToken))

	// Corrupt pk token payload
	pkt.Payload = []byte(`{"`)

	uiRequester, err := verifier.NewUserInfoRequester(pkt, string(accessToken))
	require.ErrorContains(t, err, "malformatted PK token claims")
	require.Nil(t, uiRequester)

	// Use incorrect type for pk token sub claim
	pkt.Payload = []byte(`{"issuer": "https://accounts.example.com", "sub": {}}`)
	uiRequester, err = verifier.NewUserInfoRequester(pkt, string(accessToken))
	require.ErrorContains(t, err, "malformatted PK token claims")
	require.Nil(t, uiRequester)
}

// TestUserInfoNonBooleanVerifiedClaims covers userinfo responses whose
// boolean-valued claims arrive in shapes the zitadel/oidc oidc.UserInfo type
// refuses to decode.
//
// zitadel/oidc v4 made oidc.Bool.UnmarshalJSON return an error for any value
// that is not a JSON boolean or the strings "true"/"false", and promoted
// phone_number_verified from a plain bool to oidc.Bool. Decoding into
// oidc.UserInfo would therefore fail the entire request for a provider that
// sends "email_verified": null. We decode into a passthrough type instead, so
// these responses must succeed and the claims must reach the caller exactly
// as the provider sent them.
func TestUserInfoNonBooleanVerifiedClaims(t *testing.T) {
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

	accessToken := string(opkClient.GetAccessToken())
	require.NotEmpty(t, accessToken)

	tests := []struct {
		name        string
		response    string
		expectClaim string
	}{
		{
			name:        "boolean true",
			response:    `{"sub": "me", "email": "alice@example.com", "email_verified": true}`,
			expectClaim: `"email_verified":true`,
		},
		{
			name:        "string boolean from a non-compliant OP is preserved",
			response:    `{"sub": "me", "email": "alice@example.com", "email_verified": "true"}`,
			expectClaim: `"email_verified":"true"`,
		},
		{
			name:        "null email_verified does not fail the request",
			response:    `{"sub": "me", "email": "alice@example.com", "email_verified": null}`,
			expectClaim: `"email_verified":null`,
		},
		{
			name:        "null phone_number_verified does not fail the request",
			response:    `{"sub": "me", "phone_number_verified": null}`,
			expectClaim: `"phone_number_verified":null`,
		},
		{
			name:        "numeric email_verified does not fail the request",
			response:    `{"sub": "me", "email_verified": 1}`,
			expectClaim: `"email_verified":1`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uiRequester, err := verifier.NewUserInfoRequester(pkt, accessToken)
			require.NoError(t, err)
			uiRequester.HttpClient = mocks.NewMockGoogleUserInfoHTTPClient(tt.response, accessToken)

			userInfoJson, err := uiRequester.Request(context.Background())
			require.NoError(t, err)
			require.Contains(t, userInfoJson, tt.expectClaim)
			// The sub claim must still be present and verified against the ID token.
			require.Contains(t, userInfoJson, `"sub":"me"`)
		})
	}
}

// TestUserInfoSubMismatchStillRejected guards the security property that the
// passthrough decoding must not weaken: a userinfo response whose sub does not
// match the ID token subject is still rejected.
func TestUserInfoSubMismatchStillRejected(t *testing.T) {
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

	accessToken := string(opkClient.GetAccessToken())
	require.NotEmpty(t, accessToken)

	uiRequester, err := verifier.NewUserInfoRequester(pkt, accessToken)
	require.NoError(t, err)
	uiRequester.HttpClient = mocks.NewMockGoogleUserInfoHTTPClient(
		`{"sub": "somebody-else", "email": "mallory@example.com"}`, accessToken)

	userInfoJson, err := uiRequester.Request(context.Background())
	require.Error(t, err)
	require.Empty(t, userInfoJson)
	require.ErrorIs(t, err, rp.ErrUserInfoSubNotMatching)
}
