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
	_ "embed"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/util"
	"github.com/sirupsen/logrus"
)

//go:embed static/*
var staticFiles embed.FS

// TODO: Add instructions on how to add a new OpenID Provider to the web chooser

type WebChooser struct {
	OpList        []providers.BrowserOpenIdProvider
	opSelected    providers.BrowserOpenIdProvider
	OpenBrowser   bool
	useMockServer bool
	mockServer    *httptest.Server
	server        *http.Server
}

func NewWebChooser(opList []providers.BrowserOpenIdProvider) *WebChooser {
	return &WebChooser{
		OpList:        opList,
		OpenBrowser:   true,
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
	mux.Handle("/choose/", http.StripPrefix("/choose/", http.FileServer(http.FS(staticContent))))
	mux.HandleFunc("/select/", func(w http.ResponseWriter, r *http.Request) {
		// Once we redirect to the OP localhost webserver, we can shutdown the web chooser localhost server
		shutdownServer := func() {
			go func() { // Put this in a go func so that it will not block the redirect
				if wc.server != nil {
					if err := wc.server.Shutdown(context.Background()); err != nil {
						logrus.Errorf("Failed to shutdown http server: %v", err)
					}
				}
			}()
		}
		defer shutdownServer()

		opName := r.URL.Query().Get("op")
		if opName == "" {
			http.Error(w, "missing op parameter", http.StatusBadRequest)
			return
		}
		if op, ok := providerMap[opName]; !ok {
			errorString := fmt.Sprintf("unknown OpenID Provider: %s", opName)
			http.Error(w, errorString, http.StatusBadRequest)
			errCh <- fmt.Errorf(errorString)
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
			err = wc.server.Serve(listener)
			if err != nil && err != http.ErrServerClosed {
				logrus.Error(err)
			}
		}()

		if wc.OpenBrowser {
			loginURI := fmt.Sprintf("http://%s/choose", listener.Addr().String())
			logrus.Infof("Opening browser to %s", loginURI)
			if err := util.OpenUrl(loginURI); err != nil {
				logrus.Errorf("Failed to open url: %v", err)
			}
		}
	}

	select {
	case err := <-errCh:
		return nil, err
	case wc.opSelected = <-opCh:
		return wc.opSelected, nil
	}
}

func IssuerToName(issuer string) (string, error) {
	// TODO: Make these constants or use an enum
	switch {
	case strings.HasPrefix(issuer, "https://accounts.google.com"):
		return "google", nil
	case strings.HasPrefix(issuer, "https://login.microsoftonline.com"):
		return "azure", nil
	default:
		return "", fmt.Errorf("unknown OpenID Provider issuer: %s", issuer)
	}
}
