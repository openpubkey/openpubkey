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
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/openpubkey/openpubkey/providers"
	"github.com/stretchr/testify/require"
)

const manualBrowserMessage = "Open your browser to:"

func CreateServerToHandleRedirect(t *testing.T) (*httptest.Server, string, <-chan struct{}) {
	redirected := make(chan struct{}, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		select {
		case redirected <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusOK)
	})
	mockServer := httptest.NewUnstartedServer(mux)
	mockServer.Start()
	return mockServer, mockServer.URL + "/redirect", redirected
}

func TestGoogleSelection(t *testing.T) {
	t.Parallel()
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
		{name: "select hello", providerName: "hello", httpCodeExpected: http.StatusOK},
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

			helloOpOptions := providers.GetDefaultHelloOpOptions()
			helloOp := providers.NewHelloOpWithOptions(helloOpOptions)

			webChooser := WebChooser{
				OpList: []providers.BrowserOpenIdProvider{
					googleOp, azureOp, gitlabOp, helloOp,
				},
				OpenBrowser:   false,
				useMockServer: true,
			}
			chooserURICh := make(chan string, 1)
			webChooser.SetLoginURIHook(func(uri string) error {
				chooserURICh <- uri
				return nil
			})

			var chooserErr error
			var op providers.OpenIdProvider

			redirectServer, redirectUri, redirected := CreateServerToHandleRedirect(t)

			testRunDone := make(chan struct{})
			go func() {
				defer close(testRunDone)
				defer redirectServer.Close()

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
					googleOp.(*providers.GoogleOp).TriggerBrowserWindowHook(redirectUri)
				case "azure":
					azureOp.(*providers.AzureOp).TriggerBrowserWindowHook(redirectUri)
				case "gitlab":
					gitlabOp.(*providers.GitlabOp).TriggerBrowserWindowHook(redirectUri)
				case "hello":
					helloOp.(*providers.HelloOp).TriggerBrowserWindowHook(redirectUri)
				default:
					// Trigger azure even if the provider doesn't match to sure this test finishes
					azureOp.(*providers.StandardOp).TriggerBrowserWindowHook(redirectUri)
				}

				select {
				case <-redirected:
				case <-time.After(time.Second):
					t.Error("redirect not triggered but should have been")
				}
			}()

			var chooserURI string
			select {
			case chooserURI = <-chooserURICh:
			case <-time.After(3 * time.Second):
				t.Fatal("web chooser server did not start")
			}

			// Make a request to the server to trigger Google selection and get redirect
			parsedChooserURI, err := url.Parse(chooserURI)
			require.NoError(t, err)
			resp, err := http.Get(parsedChooserURI.Scheme + "://" + parsedChooserURI.Host + "/select?op=" + tc.providerName)
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
			case <-time.After(5 * time.Second):
				t.Fatal("test timed out")
			}
			require.Eventually(t, func() bool {
				return listenerClosed(chooserURI)
			}, time.Second, 10*time.Millisecond, "web chooser listener remained open")
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

func TestLoginURIHookReceivesChooserURI(t *testing.T) {
	googleOp := providers.NewGoogleOpWithOptions(providers.GetDefaultGoogleOpOptions())
	webChooser := NewWebChooser([]providers.BrowserOpenIdProvider{googleOp}, false)

	expectedErr := errors.New("application could not present chooser URL")
	var authorizationURL string
	webChooser.SetLoginURIHook(func(url string) error {
		authorizationURL = url
		return expectedErr
	})

	op, err := webChooser.ChooseOp(context.Background())
	require.Nil(t, op)
	require.ErrorIs(t, err, expectedErr)
	require.Contains(t, authorizationURL, "/chooser")
}

func TestLoginURIHookReceivesURIWhenBrowserOpenFails(t *testing.T) {
	googleOp := providers.NewGoogleOpWithOptions(providers.GetDefaultGoogleOpOptions())
	webChooser := NewWebChooser([]providers.BrowserOpenIdProvider{googleOp}, true)

	ctx, cancel := context.WithCancel(context.Background())
	expectedOpenErr := errors.New("browser unavailable")
	var output, errorOutput bytes.Buffer
	webChooser.SetOutWriter(&output)
	webChooser.SetErrWriter(&errorOutput)
	webChooser.browserOpener = func(string) error {
		cancel()
		return expectedOpenErr
	}

	var authorizationURL string
	webChooser.SetLoginURIHook(func(url string) error {
		authorizationURL = url
		return nil
	})

	op, err := webChooser.ChooseOp(ctx)
	require.Nil(t, op)
	require.ErrorIs(t, err, context.Canceled)
	require.NotErrorIs(t, err, expectedOpenErr)
	require.Contains(t, authorizationURL, "/chooser")
	require.Equal(t, 1, strings.Count(output.String(), manualBrowserMessage))
	require.Contains(t, errorOutput.String(), "Failed to open URL: browser unavailable")
}

func TestPresentChooserURIOutput(t *testing.T) {
	googleOp := providers.NewGoogleOpWithOptions(providers.GetDefaultGoogleOpOptions())

	testCases := []struct {
		name               string
		openBrowser        bool
		browserOpener      func(string) error
		expectedPrintCount int
		expectOpenError    bool
	}{
		{
			name: "auto open success",
			browserOpener: func(string) error {
				return nil
			},
			openBrowser:        true,
			expectedPrintCount: 0,
		},
		{
			name: "auto open failure",
			browserOpener: func(string) error {
				return errors.New("browser unavailable")
			},
			openBrowser:        true,
			expectedPrintCount: 1,
			expectOpenError:    true,
		},
		{
			name:               "manual open",
			openBrowser:        false,
			expectedPrintCount: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())

			webChooser := NewWebChooser([]providers.BrowserOpenIdProvider{googleOp}, tc.openBrowser)
			var output, errorOutput bytes.Buffer
			webChooser.SetOutWriter(&output)
			webChooser.SetErrWriter(&errorOutput)

			if tc.browserOpener != nil {
				webChooser.browserOpener = func(uri string) error {
					err := tc.browserOpener(uri)
					cancel()
					return err
				}
			} else {
				go func() {
					time.Sleep(10 * time.Millisecond)
					cancel()
				}()
			}

			op, err := webChooser.ChooseOp(ctx)
			require.Nil(t, op)
			require.ErrorIs(t, err, context.Canceled)
			require.Equal(t, tc.expectedPrintCount, strings.Count(output.String(), manualBrowserMessage))
			if tc.expectOpenError {
				require.Contains(t, errorOutput.String(), "Failed to open URL: browser unavailable")
			}
		})
	}
}

func TestWebChooserProviderWriterInheritance(t *testing.T) {
	provider := providers.NewGoogleOpWithOptions(providers.GetDefaultGoogleOpOptions())
	standardProvider := provider.(*providers.GoogleOp)

	var chooserOut, chooserErr bytes.Buffer
	webChooser := NewWebChooser([]providers.BrowserOpenIdProvider{provider}, false)
	webChooser.SetOutWriter(&chooserOut)
	webChooser.SetErrWriter(&chooserErr)
	webChooser.setProviderDefaultWriters(provider)

	require.Same(t, &chooserOut, standardProvider.OutputWriter)
	require.Same(t, &chooserErr, standardProvider.ErrorWriter)

	var providerOut, providerErr bytes.Buffer
	standardProvider.SetOutWriter(&providerOut)
	standardProvider.SetErrWriter(&providerErr)
	webChooser.setProviderDefaultWriters(provider)

	require.Same(t, &providerOut, standardProvider.OutputWriter)
	require.Same(t, &providerErr, standardProvider.ErrorWriter)
}

type channelWriter chan string

func (w channelWriter) Write(p []byte) (int, error) {
	w <- string(p)
	return len(p), nil
}

func TestBrowserOpenOverrideWritesAsyncSelectionError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/select" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	output := make(channelWriter, 1)
	handler := newBrowserOpenOverride("google", func() io.Writer { return output })
	require.NoError(t, handler(server.URL))

	select {
	case message := <-output:
		require.Contains(t, message, "Failed to select OP: received status 500")
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for asynchronous chooser error")
	}
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

	name, err = IssuerToName("https://noterror.example.com")
	require.NoError(t, err)
	require.Equal(t, "noterror.example.com", name)

	name, err = IssuerToName("http://localhost")
	require.NoError(t, err)
	require.Equal(t, "localhost", name)

	name, err = IssuerToName("error.example.com")
	require.ErrorContains(t, err, "invalid OpenID Provider issuer: error.example.com")
	require.Equal(t, "", name)
}

func TestChooseOpAuthWaitTimeout(t *testing.T) {
	googleOp := providers.NewGoogleOpWithOptions(providers.GetDefaultGoogleOpOptions())
	webChooser := NewWebChooser([]providers.BrowserOpenIdProvider{googleOp}, false)
	webChooser.AuthWaitTimeout = 50 * time.Millisecond
	var chooserURI string
	webChooser.SetLoginURIHook(func(uri string) error {
		chooserURI = uri
		return nil
	})

	op, err := webChooser.ChooseOp(context.Background())
	require.Nil(t, op)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Contains(t, err.Error(), "authentication timed out after waiting 50ms")
	requireListenerClosed(t, chooserURI)
}

func requireListenerClosed(t *testing.T, rawURL string) {
	t.Helper()
	require.True(t, listenerClosed(rawURL), "callback listener is still accepting connections")
}

func listenerClosed(rawURL string) bool {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	connection, err := net.DialTimeout("tcp", parsedURL.Host, 100*time.Millisecond)
	if connection != nil {
		_ = connection.Close()
	}
	return err != nil
}
