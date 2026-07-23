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
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"time"

	"github.com/openpubkey/openpubkey/internal/httpserver"
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
	util.OutOrErrWriter
	OpList      []providers.BrowserOpenIdProvider
	opSelected  providers.BrowserOpenIdProvider
	OpenBrowser bool
	// AuthWaitTimeout bounds how long ChooseOp waits for the user to pick a
	// provider in the browser. Zero means providers.DefaultAuthWaitTimeout
	// (10 minutes). A negative value disables the library timeout so only the
	// parent context can cancel the wait.
	AuthWaitTimeout time.Duration
	useMockServer   bool
	server          *http.Server
	loginURIHook    LoginURIHook
	// browserOpener replaces util.OpenUrl in tests that exercise browser-open
	// success and failure paths.
	browserOpener func(string) error
}

// LoginURIHook receives the web chooser URI.
//
// The hook is called before automatic browser opening is attempted. This
// ensures the application receives the URI even if the browser cannot be
// opened. When automatic browser opening is disabled, the application can use
// the hook to display the URI, open a browser, or integrate the URI into its
// own user interface. Returning an error aborts provider selection and is
// returned by WebChooser.ChooseOp. If automatic browser opening fails after a
// hook has received the URI, the opening error is not returned; the hook
// is expected to have made the URI available through an application-controlled
// mechanism.
type LoginURIHook func(uri string) error

// BrowserOpenOverrideFunc is retained for source compatibility.
// Deprecated: use LoginURIHook.
type BrowserOpenOverrideFunc = LoginURIHook

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
	authCtx, cancelAuth := providers.WithAuthWaitTimeout(ctx, wc.AuthWaitTimeout)
	chooseDone := make(chan struct{})
	defer close(chooseDone)
	shutdownCh := make(chan struct{}, 1)

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
		defer func() {
			select {
			case shutdownCh <- struct{}{}:
			default:
			}
		}()

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
			wc.setProviderDefaultWriters(op)
			redirectUriCh := make(chan string, 1)
			op.ReuseBrowserWindowHook(redirectUriCh)
			// Publish the provider only after its browser-window hook is fully
			// configured. The caller may begin RequestTokens as soon as it
			// receives op, and that method reads the hook.
			select {
			case opCh <- op:
			case <-r.Context().Done():
				return
			}

			select {
			case redirectURI := <-redirectUriCh:
				http.Redirect(w, r, redirectURI, http.StatusFound)
			case <-r.Context().Done():
				return
			}
		}
	})

	var callbackServer *http.Server
	var testServer *httptest.Server
	if wc.useMockServer {
		testServer = httptest.NewUnstartedServer(mux)
		testServer.Config.BaseContext = func(net.Listener) context.Context { return authCtx }
		testServer.Start()
		callbackServer = testServer.Config
		if wc.loginURIHook != nil {
			if err := wc.loginURIHook(testServer.URL + "/chooser"); err != nil {
				cancelAuth()
				_ = callbackServer.Close()
				testServer.Close()
				return nil, fmt.Errorf("login URI hook failed: %w", err)
			}
		}
	} else {
		listener, err := net.Listen("tcp", "localhost:0")
		if err != nil {
			cancelAuth()
			return nil, fmt.Errorf("failed to bind to an available port: %w", err)
		}
		wc.server = &http.Server{
			Handler:     mux,
			BaseContext: func(net.Listener) context.Context { return authCtx },
		}
		callbackServer = wc.server
		go func() {
			serveErr := callbackServer.Serve(listener)
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				select {
				case errCh <- fmt.Errorf("web chooser server failed: %w", serveErr):
				case <-authCtx.Done():
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

		if wc.loginURIHook != nil {
			if err := wc.loginURIHook(loginURI); err != nil {
				cancelAuth()
				_ = callbackServer.Close()
				return nil, fmt.Errorf("login URI hook failed: %w", err)
			}
		}

		wc.presentChooserURI(loginURI)

	}

	// The server outlives ChooseOp after a successful selection so it can
	// redirect the same browser window to the selected provider. Its lifecycle
	// goroutine retains the auth deadline and owns final cleanup.
	go func(server *http.Server, testServer *httptest.Server) {
		defer func() {
			// Do not cancel authCtx until ChooseOp has consumed the provider or
			// handler error; otherwise cleanup could mask that result as a
			// context cancellation.
			<-chooseDone
			cancelAuth()
		}()
		select {
		case <-shutdownCh:
			if err := httpserver.Shutdown(server, time.Second); err != nil {
				select {
				case errCh <- fmt.Errorf("failed to shutdown HTTP server: %w", err):
				default:
				}
			}
		case <-authCtx.Done():
			_ = server.Close()
		}
		if testServer != nil {
			testServer.Close()
		}
	}(callbackServer, testServer)

	select {
	case <-authCtx.Done():
		_ = callbackServer.Close()
		return nil, providers.AuthWaitError(authCtx, wc.AuthWaitTimeout)
	case err := <-errCh:
		cancelAuth()
		_ = callbackServer.Close()
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

		} else if strings.HasPrefix(issuer, "http://localhost") {
			// Needed for OPs that run on localhost. Useful for testing against custom OP integrations.
			return strings.Split(strings.TrimPrefix(issuer, "http://"), "/")[0], nil
		}
		return "", fmt.Errorf("invalid OpenID Provider issuer: %s", issuer)
	}
}

// SetLoginURIHook sets the application callback that handles or
// observes the chooser URI. See LoginURIHook for invocation and
// error semantics.
func (wc *WebChooser) SetLoginURIHook(hook LoginURIHook) {
	wc.loginURIHook = hook
}

// presentChooserURI opens or prints the web chooser URI. Automatic opening is
// attempted when enabled, and the URI is printed only if the user must navigate
// manually.
func (wc *WebChooser) presentChooserURI(uri string) {
	needsManual := !wc.OpenBrowser
	if wc.OpenBrowser {
		_, _ = fmt.Fprintf(wc.OutWriter(), "Opening browser to %s\n", uri)
		browserOpener := wc.browserOpener
		if browserOpener == nil {
			browserOpener = util.OpenUrl
		}
		if err := browserOpener(uri); err != nil {
			_, _ = fmt.Fprintf(wc.ErrWriter(), "Failed to open URL: %v\n", err)
			needsManual = true
		}
	}
	if needsManual {
		_, _ = fmt.Fprintf(wc.OutWriter(), "Open your browser to: %s\n", uri)
	}
}

func (wc *WebChooser) setProviderDefaultWriters(provider providers.BrowserOpenIdProvider) {
	providers.SetDefaultWriters(provider, wc.OutWriter(), wc.ErrWriter())
}

// SetOpenBrowserOverride sets a function that receives the chooser URI.
// Callback errors continue to be returned by ChooseOp, preserving the
// historical behavior of this deprecated API.
// Deprecated: use SetLoginURIHook.
func (wc *WebChooser) SetOpenBrowserOverride(fn BrowserOpenOverrideFunc) {
	wc.SetLoginURIHook(fn)
}
