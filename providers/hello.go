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
	"github.com/openpubkey/openpubkey/providers/mocks"
)

const helloIssuer = "https://issuer.hello.coop"

// HelloOptions is an options struct that configures how providers.HelloOp
// operates. See providers.GetDefaultGoogleOpOptions for the recommended default
// values to use when interacting with Google as the OpenIdProvider.
type HelloOptions struct {
	// ClientID is the client ID of the OIDC application. It should be the
	// expected "aud" claim in received ID tokens from the OP.
	ClientID string
	// Issuer is the OP's issuer URI for performing OIDC authorization and
	// discovery.
	Issuer string
	// Scopes is the list of scopes to send to the OP in the initial
	// authorization request.
	Scopes []string
	// PromptType is the type of prompt to use when requesting authorization from the user. Typically
	// this is set to "consent".
	PromptType string
	// AccessType is the type of access to request from the OP. Typically this is set to "offline".
	AccessType string
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

func GetDefaultHelloOpOptions() *HelloOptions {
	return &HelloOptions{
		Issuer:     helloIssuer,
		ClientID:   "app_xejobTKEsDNSRd5vofKB2iay_2rN",
		Scopes:     []string{"openid profile email"},
		PromptType: "consent",
		AccessType: "offline",
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

// NewHelloOp creates a Hello OP (OpenID Provider) using the
// default configurations options. It uses the OIDC Relying Party (Client)
// setup by the OpenPubkey project.
func NewHelloOp() BrowserOpenIdProvider {
	options := GetDefaultHelloOpOptions()
	return NewHelloOpWithOptions(options)
}

// NewHelloKeyBindingOp creates a Hello OP (OpenID Provider) with key binding that supports the OpenID key binding protocol
// using the default configurations options. It uses the OIDC Relying Party (Client)
// setup by the OpenPubkey project.
func NewHelloKeyBindingOp() OpenIdProvider {
	options := GetDefaultHelloOpOptions()
	return NewHelloKeyBindingOpWithOptions(options)
}

// NewHelloOpWithOptions creates a Hello OP with configuration specified
// using an options struct. This is useful if you want to use your own OIDC
// Client or override the configuration.
func NewHelloOpWithOptions(opts *HelloOptions) BrowserOpenIdProvider {
	return newHelloOpWithOptions(opts)
}

func newHelloOpWithOptions(opts *HelloOptions) *HelloOp {
	return &HelloOp{
		clientID:                  opts.ClientID,
		Scopes:                    opts.Scopes,
		RedirectURIs:              opts.RedirectURIs,
		PromptType:                opts.PromptType,
		AccessType:                opts.AccessType,
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

// NewHelloKeyBindingOpWithOptions creates a Hello key binding OP with configuration specified
// using an options struct. This is useful if you want to use your own OIDC
// Client or override the configuration.
func NewHelloKeyBindingOpWithOptions(opts *HelloOptions) BrowserOpenIdProvider {
	return &HelloKeyBindingOp{
		StandardOp: *newHelloOpWithOptions(opts),
	}
}

type HelloOp = StandardOp

var _ OpenIdProvider = (*HelloOp)(nil)
var _ BrowserOpenIdProvider = (*HelloOp)(nil)

type HelloKeyBindingOp = KeyBindingOp

var _ OpenIdProvider = (*HelloKeyBindingOp)(nil)
var _ BrowserOpenIdProvider = (*HelloKeyBindingOp)(nil)

func CreateMockHelloOpWithOpts(helloOpOpts *HelloOptions, userActions mocks.UserBrowserInteractionMock) (BrowserOpenIdProvider, error) {
	subjects := []mocks.Subject{
		{
			SubjectID: "alice@gmail.com",
		},
	}

	idp, err := mocks.NewMockOp(helloOpOpts.Issuer, subjects)
	if err != nil {
		return nil, err
	}

	expSigningKey, expKeyID, expRecord := idp.RandomSigningKey()
	idp.MockProviderBackend.IDTokenTemplate = &mocks.IDTokenTemplate{
		CommitFunc:           mocks.AddNonceCommit,
		Issuer:               helloOpOpts.Issuer,
		Nonce:                "empty",
		NoNonce:              false,
		Aud:                  helloOpOpts.ClientID,
		KeyID:                expKeyID,
		NoKeyID:              false,
		Alg:                  expRecord.Alg,
		NoAlg:                false,
		ExtraClaims:          map[string]any{"extraClaim": "extraClaimValue"},
		ExtraProtectedClaims: map[string]any{"extraHeader": "extraheaderValue"},
		SigningKey:           expSigningKey,
	}

	rt := idp.GetHTTPClient()
	helloOpOpts.HttpClient = rt
	helloOpOpts.OpenBrowser = false // Don't open the browser in tests

	helloOp := NewHelloOpWithOptions(helloOpOpts)

	browserOpenOverrideFn := userActions.BrowserOpenOverrideFunc(idp)
	op := helloOp.(*StandardOp)
	op.SetOpenBrowserOverride(browserOpenOverrideFn)

	return op, nil
}

func CreateMockHelloKeyBindingOpWithOpts(helloOpOpts *HelloOptions, userActions mocks.UserBrowserInteractionMock) (BrowserOpenIdProvider, error) {
	subjects := []mocks.Subject{
		{
			SubjectID: "alice@gmail.com",
		},
	}

	idp, err := mocks.NewMockKeyBindingOp(helloOpOpts.Issuer, subjects)
	if err != nil {
		return nil, err
	}

	expSigningKey, expKeyID, expRecord := idp.RandomSigningKey()
	idp.MockProviderBackend.IDTokenTemplate = &mocks.IDTokenTemplate{
		CommitFunc:           mocks.AddNonceCommit,
		Issuer:               helloOpOpts.Issuer,
		Nonce:                "empty",
		NoNonce:              false,
		Aud:                  helloOpOpts.ClientID,
		KeyID:                expKeyID,
		NoKeyID:              false,
		Alg:                  expRecord.Alg,
		NoAlg:                false,
		ExtraClaims:          map[string]any{"extraClaim": "extraClaimValue"},
		ExtraProtectedClaims: map[string]any{"extraHeader": "extraheaderValue"},
		SigningKey:           expSigningKey,
	}

	rt := idp.GetHTTPClient()
	helloOpOpts.HttpClient = rt
	helloOpOpts.OpenBrowser = false // Don't open the browser in tests

	// TODO: Determine where to put "key binding" in names
	helloOp := NewHelloKeyBindingOpWithOptions(helloOpOpts)

	browserOpenOverrideFn := userActions.BrowserOpenOverrideFunc(idp)
	op := helloOp.(*HelloKeyBindingOp)
	op.SetOpenBrowserOverride(browserOpenOverrideFn)

	return op, nil
}
