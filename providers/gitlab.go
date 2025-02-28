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
	"context"
	"net/http"
	"time"

	"github.com/openpubkey/openpubkey/discover"
)

type GitlabOptions struct {
	// ClientID is the client ID of the OIDC application. It should be the
	// expected "aud" claim in received ID tokens from the OP.
	ClientID string
	// ClientSecret is the client secret of the OIDC application. Some OPs do
	// not require that this value is set.
	ClientSecret string
	// Issuer is the OP's issuer URI for performing OIDC authorization and
	// discovery.
	Issuer string
	// Scopes is the list of scopes to send to the OP in the initial
	// authorization request.
	Scopes []string
	// RedirectURIs is the list of authorized redirect URIs that can be
	// redirected to by the OP after the user completes the authorization code
	// flow exchange. Ensure that your OIDC application is configured to accept
	// these URIs otherwise an error may occur.
	RedirectURIs []string
	// GQSign denotes if the received ID token should be upgraded to a GQ token
	// using GQ signatures.
	GQSign bool
	// OpenBrowser denotes if the client's default browser should be opened
	// automatically when performing the OIDC authorization flow. This value
	// should typically be set to true, unless performing some headless
	// automation (e.g. integration tests) where you don't want the browser to
	// open.
	OpenBrowser bool
	// HttpClient is the http.Client to use when making queries to the OP (OIDC
	// code exchange, refresh, verification of ID token, fetch of JWKS endpoint,
	// etc.). If nil, then http.DefaultClient is used.
	HttpClient *http.Client
	// IssuedAtOffset configures the offset to add when validating the "iss" and
	// "exp" claims of received ID tokens from the OP.
	IssuedAtOffset time.Duration
}

func GetDefaultGitlabOpOptions() *GitlabOptions {
	return &GitlabOptions{
		ClientID: "8d8b7024572c7fd501f64374dec6bba37096783dfcd792b3988104be08cb6923",
		Issuer:   gitlabIssuer,
		Scopes:   []string{"openid email"},
		RedirectURIs: []string{
			"http://localhost:3000/login-callback",
			"http://localhost:10001/login-callback",
			"http://localhost:11110/login-callback",
		},
		GQSign:         false,
		OpenBrowser:    true,
		HttpClient:     nil,
		IssuedAtOffset: 1 * time.Minute,
	}
}

func NewGitlabOpWithOptions(opts *GitlabOptions) BrowserOpenIdProvider {
	return &StandardOp{
		clientID:                  opts.ClientID,
		Scopes:                    opts.Scopes,
		RedirectURIs:              opts.RedirectURIs,
		GQSign:                    opts.GQSign,
		OpenBrowser:               opts.OpenBrowser,
		HttpClient:                opts.HttpClient,
		IssuedAtOffset:            opts.IssuedAtOffset,
		issuer:                    opts.Issuer,
		requestTokensOverrideFunc: nil,
		publicKeyFinder: discover.PublicKeyFinder{
			JwksFunc: func(ctx context.Context, issuer string) ([]byte, error) {
				return discover.GetJwksByIssuer(ctx, issuer, opts.HttpClient)
			},
		},
	}
}
