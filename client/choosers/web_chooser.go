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

package choosers

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"text/template"

	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/util"
	"github.com/sirupsen/logrus"
)

// TODO: Add instructions on how to add a new OpenID Provider to the web chooser

type Server struct {
}

func NewChooserServer() (*Server, error) {
	server := &Server{}
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir("chooser/static")))
	err := http.ListenAndServe(":3003", mux)
	return server, err
}

func NewWebChooser(opList []providers.BrowserOpenIdProvider) *WebChooser {
	return &WebChooser{
		OpList:      opList,
		OpenBrowser: true,
	}
}

type WebChooser struct {
	OpList      []providers.BrowserOpenIdProvider
	opSelected  providers.BrowserOpenIdProvider
	OpenBrowser bool
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

	// Parse the HTML template
	tmpl, err := template.New("chooser").Parse(templateHtml)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, fmt.Errorf("failed to bind to an available port: %w", err)
	}

	mux := http.NewServeMux()
	server := &http.Server{Handler: mux}
	mux.HandleFunc("/choose", func(w http.ResponseWriter, r *http.Request) {
		data := struct {
			GoogleUri string
			AzureUri  string
		}{
			GoogleUri: "/select?op=google",
			AzureUri:  "/select?op=azure",
		}
		w.Header().Set("Content-Type", "text/html")
		if err := tmpl.Execute(w, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	if wc.OpenBrowser {
		loginURI := fmt.Sprintf("http://%s/choose", listener.Addr().String())
		logrus.Infof("Opening browser to %s", loginURI)
		if err := util.OpenUrl(loginURI); err != nil {
			logrus.Errorf("Failed to open url: %v", err)
		}
	}

	opCh := make(chan providers.BrowserOpenIdProvider, 1)
	errCh := make(chan error, 1)
	mux.HandleFunc("/select/", func(w http.ResponseWriter, r *http.Request) {
		opName := r.URL.Query().Get("op")
		if opName == "" {
			http.Error(w, "missing op parameter", http.StatusBadRequest)
			return
		}
		if op, ok := providerMap[opName]; !ok {
			errorString := fmt.Sprintf("unknown OpenID Provider: %s", opName)
			http.Error(w, errorString, http.StatusBadRequest)
			errCh <- fmt.Errorf(errorString)
		} else {
			opCh <- op

			redirCh := make(chan string, 1)
			op.ReuseBrowserWindowHook(redirCh)
			redirectUri := <-redirCh
			http.Redirect(w, r, redirectUri, http.StatusFound)

			// Once we redirect to the OP localhost webserver, we can shutdown the web chooser localhost server
			shutdownServer := func() {
				go func() { // Put this in a go func so that it will not block the redirect
					if err := server.Shutdown(context.Background()); err != nil {
						logrus.Errorf("Failed to shutdown http server: %v", err)
					}
				}()
			}
			defer shutdownServer()
		}
	})

	go func() {
		err := server.Serve(listener)
		if err != nil && err != http.ErrServerClosed {
			logrus.Error(err)
		}
	}()

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

// TODO: Break this out into a file
const templateHtml = `
<!DOCTYPE html>
<html>
    <head>
        <title>OpenPubkey: OpenID Providers</title>
        <style>
            body {
                text-align: center;
                font-family: Arial, sans-serif;
                background-color: #f0f0f0;
            }
            .g_id_signin {
                margin-top: 100px;
            }
        </style>
    </head>
    <body>
        <div>
        <h1>OpenPubkey OpenID Providers:</h1>
        </div>
        <br>
        <a href="{{.GoogleUri}}">
            <img src="https://developers.google.com/identity/images/btn_google_signin_dark_normal_web.png" alt="Sign in with Google" />
        </a>
		<br>
		<a href="{{.AzureUri}}">
            <img src="https://learn.microsoft.com/en-us/entra/identity-platform/media/howto-add-branding-in-apps/ms-symbollockup_signin_light.svg" alt="Sign in with Azure" />
        </a>
    </body>
</html>`
