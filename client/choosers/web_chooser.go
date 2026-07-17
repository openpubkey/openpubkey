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
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"

	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/util"
)

//go:embed static/*
var staticFiles embed.FS

//go:embed chooser.tmpl
var chooserTemplateFile string

// To add support for an OP to the the WebChooser:
// 1. Add the OP to IssuerToName func
// 2. Add the OP to the html template file: `chooser.tmpl`
// 3. Add the OP to the data which is supplied to `chooserTemplate.Execute(w, data)`
//
// Note that the web chooser can only support BrowserOpenIdProvider

// TODO: This should be an enum that can also autogenerate what gets passed to the template

type WebChooser struct {
	OpList                  []providers.BrowserOpenIdProvider
	opSelected              providers.BrowserOpenIdProvider
	OpenBrowser             bool
	useMockServer           bool
	mockServer              *httptest.Server
	server                  *http.Server
	authorizationURLHandler AuthorizationURLHandler
	// outWriter receives non-fatal, user-facing messages. If nil, os.Stderr is
	// used for backward compatibility.
	outWriter io.Writer
	// browserOpener replaces util.OpenUrl in tests that exercise browser-open
	// success and failure paths.
	browserOpener func(string) error
}

// AuthorizationURLHandler receives the web chooser URL.
//
// The handler is called before automatic browser opening is attempted. This
// ensures the application receives the URL even if the browser cannot be
// opened. When automatic browser opening is disabled, the application can use
// the handler to display the URL, open a browser, or integrate the URL into its
// own user interface. Returning an error aborts provider selection and is
// returned by WebChooser.ChooseOp. If automatic browser opening fails after a
// handler has received the URL, the opening error is not returned; the handler
// is expected to have made the URL available through an application-controlled
// mechanism.
type AuthorizationURLHandler func(url string) error

// BrowserOpenOverrideFunc is retained for source compatibility.
// Deprecated: use AuthorizationURLHandler.
type BrowserOpenOverrideFunc = AuthorizationURLHandler

func NewWebChooser(opList []providers.BrowserOpenIdProvider, openBrowser bool) *WebChooser {
	return &WebChooser{
		OpList:        opList,
		OpenBrowser:   openBrowser,
		useMockServer: false,
	}
}

func (wc *WebChooser) ChooseOp(ctx context.Context) (providers.OpenIdProvider, error) {
	if wc.opSelected != nil {
		return nil, fmt.Errorf("provider has already been chosen")
	}

	providerMap := map[string]providers.BrowserOpenIdProvider{}
	for _, provider := range wc.OpList {
		if providerName, err := IssuerToName(provider.Issuer()); err != nil {
			return nil, err
		} else {
			if _, ok := providerMap[providerName]; ok {
				return nil, fmt.Errorf("provider in web chooser found with duplicate issuer: %s", provider.Issuer())
			}
			providerMap[providerName] = provider
		}
	}

	opCh := make(chan providers.BrowserOpenIdProvider, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	staticContent, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return nil, err
	}

	chooserTemplate, err := template.New("chooser-page").Parse(chooserTemplateFile)
	if err != nil {
		return nil, err
	}

	mux.HandleFunc("/chooser", func(w http.ResponseWriter, r *http.Request) {
		type Provider struct {
			Name   string
			Button string
		}

		data := struct {
			Providers []Provider
		}{}

		sortedProviderNames := make([]string, 0)
		for providerName := range providerMap {
			sortedProviderNames = append(sortedProviderNames, providerName)
		}
		// Sort the provider names
		sort.Strings(sortedProviderNames)

		for _, providerName := range sortedProviderNames {
			if providerName == "google" {
				data.Providers = append(data.Providers, Provider{
					Name:   providerName,
					Button: "google-light.svg",
				})
				continue
			}
			if providerName == "azure" {
				data.Providers = append(data.Providers, Provider{
					Name:   providerName,
					Button: "azure-dark.svg",
				})
				continue
			}
			if providerName == "gitlab" {
				data.Providers = append(data.Providers, Provider{
					Name:   providerName,
					Button: "gitlab-light.svg",
				})
				continue
			}
			if providerName == "hello" {
				data.Providers = append(data.Providers, Provider{
					Name:   providerName,
					Button: "hello-dark.png",
				})
				continue
			}
			data.Providers = append(data.Providers, Provider{
				Name:   providerName,
				Button: "",
			})

		}

		w.Header().Set("Content-Type", "text/html")
		if err := chooserTemplate.Execute(w, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticContent))))
	mux.HandleFunc("/select/", func(w http.ResponseWriter, r *http.Request) {
		// Once we redirect to the OP localhost webserver, we can shutdown the web chooser localhost server
		shutdownServer := func() {
			go func() { // Put this in a go func so that it will not block the redirect
				if wc.server != nil {
					if err := wc.server.Shutdown(ctx); err != nil {
						select {
						case errCh <- fmt.Errorf("failed to shutdown HTTP server: %w", err):
						default:
						}
					}
				}
			}()
		}
		defer shutdownServer()

		opName := r.URL.Query().Get("op")
		if opName == "" {
			errorString := "missing op parameter"
			http.Error(w, errorString, http.StatusBadRequest)
			errCh <- errors.New(errorString)
			return
		}
		if op, ok := providerMap[opName]; !ok {
			errorString := fmt.Sprintf("unknown OpenID Provider: %s", opName)
			http.Error(w, errorString, http.StatusBadRequest)
			errCh <- errors.New(errorString)
			return
		} else {
			opCh <- op

			redirectUriCh := make(chan string, 1)
			op.ReuseBrowserWindowHook(redirectUriCh)

			redirectUri := <-redirectUriCh
			http.Redirect(w, r, redirectUri, http.StatusFound)
		}
	})

	if wc.useMockServer {
		wc.mockServer = httptest.NewUnstartedServer(mux)
		wc.mockServer.Start()
	} else {
		listener, err := net.Listen("tcp", "localhost:0")
		if err != nil {
			return nil, fmt.Errorf("failed to bind to an available port: %w", err)
		}
		wc.server = &http.Server{Handler: mux}
		go func() {
			serveErr := wc.server.Serve(listener)
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				select {
				case errCh <- fmt.Errorf("web chooser server failed: %w", serveErr):
				case <-ctx.Done():
				}
			}
		}()

		var loginURI string
		if listener.Addr().(*net.TCPAddr).IP.String() == "127.0.0.1" {
			// For consistency in output messages in our code base we use localhost rather than 127.0.0.1
			port := listener.Addr().(*net.TCPAddr).Port
			loginURI = fmt.Sprintf("http://localhost:%d/chooser", port)
		} else {
			loginURI = fmt.Sprintf("http://%s/chooser", listener.Addr().String())
		}

		if wc.authorizationURLHandler != nil {
			if err := wc.authorizationURLHandler(loginURI); err != nil {
				_ = wc.server.Shutdown(ctx)
				return nil, fmt.Errorf("authorization URL handler failed: %w", err)
			}
		}

		if wc.OpenBrowser {
			browserOpener := wc.browserOpener
			if browserOpener == nil {
				browserOpener = util.OpenUrl
			}
			if err := browserOpener(loginURI); err != nil {
				_, _ = fmt.Fprintf(wc.outputWriter(), "Failed to open URL: %v\n", err)
				if wc.authorizationURLHandler == nil {
					// Preserve the previous continue-on-failure behavior while ensuring
					// the user can still complete authentication manually.
					_, _ = fmt.Fprintf(wc.outputWriter(), "Open your browser to: %s\n", loginURI)
				}
			}
		} else if wc.authorizationURLHandler == nil {
			// Preserve the manual-browser behavior for existing applications. New
			// applications should install an AuthorizationURLHandler and decide how
			// to present the URL.
			_, _ = fmt.Fprintf(wc.outputWriter(), "Open your browser to: %s\n", loginURI)
		}

	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-errCh:
		return nil, err
	case wc.opSelected = <-opCh:
		return wc.opSelected, nil
	}
}

func IssuerToName(issuer string) (string, error) {
	switch {
	case strings.HasPrefix(issuer, "https://accounts.google.com"):
		return "google", nil
	case strings.HasPrefix(issuer, "https://login.microsoftonline.com"):
		return "azure", nil
	case strings.HasPrefix(issuer, "https://gitlab.com"):
		return "gitlab", nil
	case strings.HasPrefix(issuer, "https://issuer.hello.coop"):
		return "hello", nil
	default:
		if after, ok := strings.CutPrefix(issuer, "https://"); ok {
			// Returns issuer without the "https://" prefix and without any path remaining on the url
			// e.g. https://accounts.google.com/fdsfa/fdsafsad -> accounts.google.com
			return strings.Split(after, "/")[0], nil

		}
		return "", fmt.Errorf("invalid OpenID Provider issuer: %s", issuer)
	}
}

// SetAuthorizationURLHandler sets the application callback that handles or
// observes the chooser URL. See AuthorizationURLHandler for invocation and
// error semantics.
func (wc *WebChooser) SetAuthorizationURLHandler(handler AuthorizationURLHandler) {
	wc.authorizationURLHandler = handler
}

// SetOutWriter configures where non-fatal, user-facing messages are written.
// Passing nil restores the default of os.Stderr.
func (wc *WebChooser) SetOutWriter(writer io.Writer) {
	wc.outWriter = writer
}

func (wc *WebChooser) outputWriter() io.Writer {
	if wc.outWriter == nil {
		return os.Stderr
	}
	return wc.outWriter
}

// SetOpenBrowserOverride sets a function that receives the chooser URL.
// Callback errors continue to be returned by ChooseOp, preserving the
// historical behavior of this deprecated API.
// Deprecated: use SetAuthorizationURLHandler.
func (wc *WebChooser) SetOpenBrowserOverride(fn BrowserOpenOverrideFunc) {
	wc.SetAuthorizationURLHandler(fn)
}
