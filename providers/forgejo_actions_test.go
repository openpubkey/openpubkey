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

package providers

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/openpubkey/openpubkey/discover"
	"github.com/openpubkey/openpubkey/providers/mocks"
	"github.com/stretchr/testify/require"
)

func TestForgejoIssuerFromTokenRequestURL(t *testing.T) {
	tests := []struct {
		name           string
		tokenURL       string
		expectedIssuer string
		expectError    bool
	}{
		{
			name:           "codeberg",
			tokenURL:       "https://codeberg.org/api/actions/_apis/pipelines/workflows/792/idtoken?placeholder=true",
			expectedIssuer: "https://codeberg.org/api/actions",
		},
		{
			name:           "self-hosted instance under sub-path",
			tokenURL:       "https://git.example.com/forgejo/api/actions/_apis/pipelines/workflows/1/idtoken?placeholder=true",
			expectedIssuer: "https://git.example.com/forgejo/api/actions",
		},
		{
			name:        "github actions URL is not a forgejo environment",
			tokenURL:    "https://pipelines.actions.githubusercontent.com/abcdef/_apis/pipelines/1/runs/2/idtoken?api-version=2.0",
			expectError: true,
		},
		{
			name:        "empty URL",
			tokenURL:    "",
			expectError: true,
		},
		{
			name:        "no host",
			tokenURL:    "/api/actions/_apis/pipelines/workflows/1/idtoken",
			expectError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer, err := ForgejoIssuerFromTokenRequestURL(tt.tokenURL)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedIssuer, issuer)
			}
		})
	}
}

func TestIsForgejoIssuer(t *testing.T) {
	require.True(t, IsForgejoIssuer("https://codeberg.org/api/actions"))
	require.True(t, IsForgejoIssuer("https://codeberg.org/api/actions/"))
	require.True(t, IsForgejoIssuer("https://git.example.com/forgejo/api/actions"))
	require.False(t, IsForgejoIssuer("https://token.actions.githubusercontent.com"))
	require.False(t, IsForgejoIssuer("https://accounts.google.com"))
	require.False(t, IsForgejoIssuer("https://gitlab.com"))
}

func TestNewForgejoOpFromEnvironment(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://codeberg.org/api/actions/_apis/pipelines/workflows/42/idtoken?placeholder=true")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runner-token")

	op, err := NewForgejoOpFromEnvironment()
	require.NoError(t, err)
	require.Equal(t, "https://codeberg.org/api/actions", op.Issuer())
}

func TestNewForgejoOpFromEnvironmentErrors(t *testing.T) {
	t.Run("missing env vars", func(t *testing.T) {
		for _, k := range []string{"ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"} {
			if orig, ok := os.LookupEnv(k); ok {
				require.NoError(t, os.Unsetenv(k))
				t.Cleanup(func() { os.Setenv(k, orig) })
			}
		}
		_, err := NewForgejoOpFromEnvironment()
		require.ErrorContains(t, err, "ACTIONS_ID_TOKEN_REQUEST_URL")
	})

	t.Run("github actions environment", func(t *testing.T) {
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://pipelines.actions.githubusercontent.com/abcdef/_apis/pipelines/1/runs/2/idtoken?api-version=2.0")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runner-token")
		_, err := NewForgejoOpFromEnvironment()
		require.ErrorContains(t, err, "not a Forgejo Actions environment")
	})
}

func TestForgejoRequestTokensAndVerifyRoundtrip(t *testing.T) {
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyID := "test-kid-1"

	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/actions/_apis/pipelines/workflows/42/idtoken", r.URL.Path)
		require.Equal(t, "Bearer runner-token", r.Header.Get("Authorization"))

		audience := r.URL.Query().Get("audience")
		require.NotEmpty(t, audience)

		idtTemplate := mocks.IDTokenTemplate{
			Issuer:     issuer,
			Aud:        audience,
			NoNonce:    true,
			KeyID:      keyID,
			Alg:        "RS256",
			SigningKey: signingKey,
			ExtraClaims: map[string]any{
				"sub":        "repo:example/repo:ref:refs/heads/main",
				"repository": "example/repo",
			},
		}
		tokens, err := idtTemplate.IssueTokens()
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(map[string]string{"value": string(tokens.IDToken)})
		require.NoError(t, err)
	}))
	defer server.Close()
	issuer = server.URL + "/api/actions"

	jwksFunc, err := discover.MockGetJwksByIssuerOneKey(signingKey.Public(), keyID, "RS256")
	require.NoError(t, err)

	op := NewForgejoOp(issuer, server.URL+"/api/actions/_apis/pipelines/workflows/42/idtoken?placeholder=true", "runner-token")
	op.publicKeyFinder = discover.PublicKeyFinder{JwksFunc: jwksFunc}

	cic := GenCIC(t)
	tokens, err := op.RequestTokens(t.Context(), cic)
	require.NoError(t, err)
	require.NotEmpty(t, tokens.IDToken)

	err = op.VerifyIDToken(t.Context(), tokens.IDToken, cic)
	require.NoError(t, err)

	// A different CIC must not verify against the same ID Token
	otherCic := GenCIC(t)
	err = op.VerifyIDToken(t.Context(), tokens.IDToken, otherCic)
	require.Error(t, err)
}

func TestForgejoRequestTokensNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer server.Close()

	op := NewForgejoOp(server.URL+"/api/actions", server.URL+"/api/actions/_apis/pipelines/workflows/42/idtoken?placeholder=true", "wrong-token")
	_, err := op.RequestTokens(t.Context(), GenCIC(t))
	require.ErrorContains(t, err, "non-200")
}

func TestForgejoRequestTokensEmptyValue(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"value": ""}`)
	}))
	defer server.Close()

	op := NewForgejoOp(server.URL+"/api/actions", server.URL+"/api/actions/_apis/pipelines/workflows/42/idtoken?placeholder=true", "runner-token")
	_, err := op.RequestTokens(t.Context(), GenCIC(t))
	require.Error(t, err)
}
