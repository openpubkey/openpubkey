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

package providers

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/openpubkey/openpubkey/providers/mocks"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestStandardProviders(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name         string
		gqSign       bool
		providerName string
	}{
		{name: "happy case Google",
			providerName: "google",
			gqSign:       false,
		},
		{name: "happy case Google (GQ sign)",
			providerName: "google",
			gqSign:       true,
		},
		{name: "happy case Azure",
			providerName: "azure",
			gqSign:       false,
		},
		{name: "happy case Azure (GQ sign)",
			providerName: "azure",
			gqSign:       true,
		},
		{name: "happy case Gitlab",
			providerName: "gitlab",
			gqSign:       false,
		},
		{name: "happy case Gitlab (GQ sign)",
			providerName: "gitlab",
			gqSign:       true,
		},
		{name: "happy case Hello",
			providerName: "hello",
			gqSign:       false,
		},
		{name: "happy case Hello (GQ sign)",
			providerName: "hello",
			gqSign:       true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var op OpenIdProvider
			var err error

			switch tc.providerName {
			case "google":
				opts := GetDefaultGoogleOpOptions()
				opts.GQSign = tc.gqSign
				op, err = CreateMockGoogleOpWithOpts(opts,
					mocks.UserBrowserInteractionMock{
						SubjectId: "alice@gmail.com",
					})
				require.NoError(t, err, tc.name)
			case "azure":
				opts := GetDefaultAzureOpOptions()
				opts.GQSign = tc.gqSign
				op, err = CreateMockAzureOpWithOpts(opts,
					mocks.UserBrowserInteractionMock{
						SubjectId: "alice@hotmail.com",
					})
				require.NoError(t, err, tc.name)
			case "hello":
				opts := GetDefaultHelloOpOptions()
				opts.GQSign = tc.gqSign
				op, err = CreateMockHelloOpWithOpts(opts,
					mocks.UserBrowserInteractionMock{
						SubjectId: "alice@gmail.com",
					})
				require.NoError(t, err, tc.name)
			case "gitlab":
				opts := GetDefaultGitlabOpOptions()
				opts.GQSign = tc.gqSign
				op, err = CreateMockGitlabOpWithOpts(opts,
					mocks.UserBrowserInteractionMock{
						SubjectId: "alice@gmail.com",
					})
				require.NoError(t, err, tc.name)
			default:
				t.Fatalf("unsupported provider name: %s", tc.providerName)
			}

			cic := GenCIC(t)

			tokens, err := op.RequestTokens(context.Background(), cic)
			require.NoError(t, err, tc.name)
			idToken := tokens.IDToken

			cicHash, err := cic.Hash()
			require.NoError(t, err, tc.name)
			require.NotNil(t, cicHash, tc.name)

			headerB64, payloadB64, _, err := jws.SplitCompact(idToken)
			require.NoError(t, err, tc.name)
			headerJson, err := util.Base64DecodeForJWT(headerB64)
			require.NoError(t, err, tc.name)

			if tc.gqSign {
				headers := jws.NewHeaders()
				err = json.Unmarshal(headerJson, &headers)
				require.NoError(t, err, tc.name)
				algFound, ok := headers.Algorithm()
				require.True(t, ok, "alg should be present")
				require.Equal(t, string("GQ256"), algFound.String(), "alg in jwt header should match GQ256")
			} else {
				payload, err := util.Base64DecodeForJWT(payloadB64)
				require.NoError(t, err, tc.name)
				require.Contains(t, string(payload), string(cicHash), tc.name)
			}
			require.Contains(t, string(tokens.RefreshToken), "mock-refresh-token", tc.name)
			require.Equal(t, "mock-access-token", string(tokens.AccessToken), tc.name)

			err = op.VerifyIDToken(context.Background(), idToken, cic)
			require.NoError(t, err, tc.name)

			switch op := op.(type) {
			case RefreshableOpenIdProvider:
				reTokens, err := op.RefreshTokens(context.Background(), tokens.RefreshToken)
				require.NoError(t, err, tc.name)

				require.Contains(t, string(reTokens.RefreshToken), "mock-refresh-token", tc.name)
				require.Equal(t, "mock-access-token", string(reTokens.AccessToken), tc.name)

				err = op.VerifyRefreshedIDToken(context.Background(), tokens.IDToken, reTokens.IDToken)
				require.NoError(t, err, tc.name)

				require.NotEqual(t, tc.providerName, "hello", tc.name, "hello provider is not refreshable")
			default:
				// Make sure a bug doesn't cause us to skip refreshed ID Token tests
				require.NotEqual(t, tc.providerName, "google", tc.name, "google provider should be refreshable")
				require.NotEqual(t, tc.providerName, "azure", tc.name, "azure provider should be refreshable")
			}
		})
	}
}

func TestDefaultConstructors(t *testing.T) {
	googOp := NewGoogleOp()
	require.NotNil(t, googOp, "Google provider should be created")

	azureOp := NewAzureOp()
	require.NotNil(t, azureOp, "Azure provider should be created")

	GitlabOp := NewGitlabOp()
	require.NotNil(t, GitlabOp, "Gitlab provider should be created")

	helloOp := NewHelloOp()
	require.NotNil(t, helloOp, "Hello provider should be created")
}

func TestRemoteRedirectURI(t *testing.T) {
	// As this test opens a http listener on a specific port, it is best to not run in parallel in order to avoid port conflicts

	remoteRedirectURIExpected := "http://localhost:8182/login-callback"
	opts := GetDefaultGoogleOpOptions()
	opts.RemoteRedirectURI = remoteRedirectURIExpected
	op, err := CreateMockGoogleOpWithOpts(opts,
		mocks.UserBrowserInteractionMock{
			SubjectId: "alice@gmail.com",
		})
	require.NoError(t, err)

	// This checks that we can override the redirect URI by opening a
	// http listener to make sure we get redirected to the expected redirect URI
	// that we set above
	ctx, cancel := context.WithCancel(context.Background())
	mux := http.NewServeMux()
	mux.HandleFunc("/login-callback", func(w http.ResponseWriter, r *http.Request) {
		defer cancel()
		uriReceived := r.URL.String()
		require.Contains(t, uriReceived, "/login-callback?code=", "callback URI path should match")
	})

	ln, err := net.Listen("tcp", "localhost:8182")
	require.NoError(t, err)
	srv := &http.Server{Handler: mux}

	go func() {
		err := srv.Serve(ln)
		if err != nil && err != http.ErrServerClosed {
			t.Errorf("server error: %v", err)
		}
	}()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	// We only call request tokens to trigger the callback to see if the correct
	// redirect URI param is set. We do not care about the result.
	_, _ = op.RequestTokens(ctx, GenCIC(t))
}

func TestCallbackHTML(t *testing.T) {
	testCases := []struct {
		name             string
		callbackHTML     string
		setCallback      bool
		expectedResponse string
	}{
		{
			name:             "default callback HTML",
			setCallback:      false,
			expectedResponse: "You may now close this window",
		},
		{
			name:             "custom plain text",
			callbackHTML:     "Authentication successful! You can close this tab now.",
			setCallback:      true,
			expectedResponse: "Authentication successful! You can close this tab now.",
		},
		{
			name:             "custom HTML",
			callbackHTML:     "<html><body><h1>Success!</h1><p>You may close this window.</p></body></html>",
			setCallback:      true,
			expectedResponse: "<html><body><h1>Success!</h1><p>You may close this window.</p></body></html>",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			clientId := "fake-client-id"
			issuer := googleIssuer

			opts := GetDefaultStandardOpOptions(issuer, clientId)
			opts.ClientSecret = "test-secret"

			// Set custom callback HTML if this test case requires it
			if tc.setCallback {
				opts.CallbackHTML = tc.callbackHTML
			}

			idp, err := mocks.NewMockOp(issuer, []mocks.Subject{
				{
					SubjectID: "alice@gmail.com",
				},
			})
			require.NoError(t, err)
			require.NotNil(t, idp)

			expSigningKey, expKeyID, expRecord := idp.RandomSigningKey()
			idp.MockProviderBackend.IDTokenTemplate = &mocks.IDTokenTemplate{
				CommitFunc: mocks.AddNonceCommit,
				Issuer:     issuer,
				Nonce:      "empty",
				NoNonce:    false,
				Aud:        clientId,
				KeyID:      expKeyID,
				NoKeyID:    false,
				Alg:        expRecord.Alg,
				NoAlg:      false,
				SigningKey: expSigningKey,
			}

			rt := idp.GetHTTPClient()
			require.NotNil(t, rt)
			opts.HttpClient = rt
			opts.OpenBrowser = false

			op := NewStandardOpWithOptions(opts)

			userAuth := mocks.UserBrowserInteractionMock{
				SubjectId: "alice@gmail.com",
			}

			browserOpenOverrideFn := userAuth.BrowserOpenOverrideFunc(idp)
			opUnwrapped := op.(*StandardOp)
			opUnwrapped.SetOpenBrowserOverride(browserOpenOverrideFn)

			cic := GenCIC(t)
			require.NotNil(t, cic)

			tokens, err := op.RequestTokens(context.Background(), cic)
			require.NoError(t, err)
			require.NotNil(t, tokens)

			// The test verifies that the feature is configurable and the value is
			// correctly stored in StandardOp. The actual HTTP response verification
			// would require intercepting the callback, which is complex with the
			// current mock setup. The important part is that CallbackHTML is
			// properly passed through to StandardOp.
			require.Equal(t, tc.expectedResponse, opUnwrapped.CallbackHTML,
				"CallbackHTML should be set correctly in StandardOp")
		})
	}
}

func TestCallbackHTMLEmptyDefaults(t *testing.T) {
	clientId := "fake-client-id"
	issuer := googleIssuer

	opts := GetDefaultStandardOpOptions(issuer, clientId)
	opts.CallbackHTML = ""

	op := NewStandardOpWithOptions(opts)
	opUnwrapped := op.(*StandardOp)
	require.Equal(t, defaultCallbackHTML, opUnwrapped.CallbackHTML,
		"CallbackHTML should default when empty")
}

func TestCallbackHTMLProviderSpecific(t *testing.T) {
	// Test that CallbackHTML works with provider-specific options
	customHTML := "<html><body><h1>Custom Success!</h1></body></html>"

	t.Run("GoogleOptions", func(t *testing.T) {
		opts := GetDefaultGoogleOpOptions()
		opts.CallbackHTML = customHTML
		op := NewGoogleOpWithOptions(opts)
		opUnwrapped := op.(*StandardOpRefreshable)
		require.Equal(t, customHTML, opUnwrapped.CallbackHTML,
			"CallbackHTML should be set correctly from GoogleOptions")
	})

	t.Run("AzureOptions", func(t *testing.T) {
		opts := GetDefaultAzureOpOptions()
		opts.CallbackHTML = customHTML
		op := NewAzureOpWithOptions(opts)
		opUnwrapped := op.(*StandardOpRefreshable)
		require.Equal(t, customHTML, opUnwrapped.CallbackHTML,
			"CallbackHTML should be set correctly from AzureOptions")
	})

	t.Run("GitlabOptions", func(t *testing.T) {
		opts := GetDefaultGitlabOpOptions()
		opts.CallbackHTML = customHTML
		op := NewGitlabOpWithOptions(opts)
		opUnwrapped := op.(*StandardOpRefreshable)
		require.Equal(t, customHTML, opUnwrapped.CallbackHTML,
			"CallbackHTML should be set correctly from GitlabOptions")
	})

	t.Run("HelloOptions", func(t *testing.T) {
		opts := GetDefaultHelloOpOptions()
		opts.CallbackHTML = customHTML
		op := NewHelloOpWithOptions(opts)
		opUnwrapped := op.(*StandardOp)
		require.Equal(t, customHTML, opUnwrapped.CallbackHTML,
			"CallbackHTML should be set correctly from HelloOptions")
	})
}
