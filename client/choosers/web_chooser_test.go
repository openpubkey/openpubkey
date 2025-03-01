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

package choosers

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/openpubkey/openpubkey/providers"
	"github.com/stretchr/testify/require"
)

func TestGoogleSelection(t *testing.T) {
	redirectUri := "http://example.com"

	testCases := []struct {
		name             string
		providerName     string
		issuerPrefix     string
		httpCodeExpected int
		errorString      string
	}{
		{name: "select google", providerName: "google", httpCodeExpected: http.StatusOK},
		{name: "select azure", providerName: "azure", httpCodeExpected: http.StatusOK},
		{name: "select gitlab", providerName: "gitlab", httpCodeExpected: http.StatusOK},
		{name: "select bad provider", providerName: "fakeProvider", httpCodeExpected: http.StatusBadRequest, errorString: "unknown OpenID Provider"},
		{name: "select no provider", providerName: "", httpCodeExpected: http.StatusBadRequest, errorString: "missing op parameter"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			googleOpOptions := providers.GetDefaultGoogleOpOptions()
			googleOp := providers.NewGoogleOpWithOptions(googleOpOptions)

			azureOpOptions := providers.GetDefaultAzureOpOptions()
			azureOp := providers.NewAzureOpWithOptions(azureOpOptions)

			gitlabOpOptions := providers.GetDefaultGitlabOpOptions()
			gitlabOp := providers.NewGitlabOpWithOptions(gitlabOpOptions)

			webChooser := WebChooser{
				OpList: []providers.BrowserOpenIdProvider{
					googleOp, azureOp, gitlabOp,
				},
				OpenBrowser:   false,
				useMockServer: true,
			}

			var chooserErr error
			var op providers.OpenIdProvider

			testRunDone := make(chan struct{})
			go func() {
				defer close(testRunDone)

				// If something goes wrong in this go func, this unittest will hang
				// until it times out. If you are running into such an issue
				// check if check if anything here is failing.
				op, chooserErr = webChooser.ChooseOp(context.Background())
				if tc.errorString != "" {
					require.ErrorContains(t, chooserErr, tc.errorString)
					require.Nil(t, op)
					return
				}
				require.NoError(t, chooserErr)
				require.NotNil(t, op)

				// trigger the redirect so the HTTP GET below will complete
				switch tc.providerName {
				case "google":
					googleOp.(*providers.StandardOp).TriggerBrowserWindowHook(redirectUri)
				case "azure":
					azureOp.(*providers.StandardOp).TriggerBrowserWindowHook(redirectUri)
				case "gitlab":
					gitlabOp.(*providers.StandardOp).TriggerBrowserWindowHook(redirectUri)
				default:
					// Trigger azure even if the provider doesn't match to sure this test finishes
					azureOp.(*providers.StandardOp).TriggerBrowserWindowHook(redirectUri)
				}
			}()

			// Wait until the server is listening
			require.Eventually(t, func() bool {
				return chooserErr != nil || webChooser.mockServer != nil && webChooser.mockServer.URL != ""
			}, 3*time.Second, 100*time.Millisecond)

			if chooserErr != nil {
				if tc.errorString != "" {
					require.ErrorContains(t, chooserErr, tc.errorString)
				} else {
					require.NoError(t, chooserErr)
				}
			}

			// Make a request to the server to trigger Google selection and get redirect
			resp, err := http.Get(webChooser.mockServer.URL + "/select?op=" + tc.providerName)
			if tc.httpCodeExpected != http.StatusOK {
				require.Equal(t, tc.httpCodeExpected, resp.StatusCode)
			} else {
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, resp.StatusCode)

				op, err = webChooser.ChooseOp(context.Background())
				require.ErrorContains(t, err, "provider has already been chosen")
				require.Nil(t, op)
			}

			// Since we use a go func inside the test, we need to ensure it finishes before we move on to the next test
			select {
			case <-testRunDone:
				require.Nil(t, nil)
			case <-time.After(5 * time.Second):
				t.Fatal("test timed out")
			}
		})
	}

}

func TestDuplicateProviderError(t *testing.T) {
	googleOpOptions := providers.GetDefaultGoogleOpOptions()
	googleOp := providers.NewGoogleOpWithOptions(googleOpOptions)

	webChooser := WebChooser{
		OpList:        []providers.BrowserOpenIdProvider{googleOp, googleOp},
		OpenBrowser:   false,
		useMockServer: true,
	}
	op, err := webChooser.ChooseOp(context.Background())
	require.ErrorContains(t, err, "provider in web chooser found with duplicate issuer: https://accounts.google.com")
	require.Nil(t, op)
}

func TestUnknownProviderError(t *testing.T) {
	googleOpOptions := providers.GetDefaultGoogleOpOptions()
	googleOpOptions.Issuer = "https://unknown-issuer.example.com"
	googleOp := providers.NewGoogleOpWithOptions(googleOpOptions)

	webChooser := WebChooser{
		OpList:        []providers.BrowserOpenIdProvider{googleOp},
		OpenBrowser:   false,
		useMockServer: true,
	}
	op, err := webChooser.ChooseOp(context.Background())
	require.ErrorContains(t, err, "unknown OpenID Provider issuer")
	require.Nil(t, op)
}

func TestIssuerToName(t *testing.T) {
	name, err := IssuerToName("https://accounts.google.com")
	require.NoError(t, err)
	require.Equal(t, "google", name)

	name, err = IssuerToName("https://login.microsoftonline.com")
	require.NoError(t, err)
	require.Equal(t, "azure", name)

	name, err = IssuerToName("https://gitlab.com")
	require.NoError(t, err)
	require.Equal(t, "gitlab", name)

	name, err = IssuerToName("https://error.example.com")
	require.ErrorContains(t, err, "unknown OpenID Provider")
	require.Equal(t, "", name)
}
