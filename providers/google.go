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
	"fmt"
	"net"
	"net/http"
	"net/url"

	"time"

	"github.com/google/uuid"
	"github.com/openpubkey/openpubkey/discover"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/util"
	"github.com/sirupsen/logrus"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	"github.com/zitadel/oidc/v2/pkg/oidc"

	httphelper "github.com/zitadel/oidc/v2/pkg/http"
)

var (
	key            = []byte("NotASecureKey123")
	issuedAtOffset = 1 * time.Minute
)

const googleIssuer = "https://accounts.google.com"

type Options struct {
	ClientID     string
	ClientSecret string
	Issuer       string // This should almost always be "https://accounts.google.com"
	Scopes       []string
	RedirectURIs []string
	SignGQ       bool
}

type GoogleOp struct {
	ClientID                 string
	ClientSecret             string
	Scopes                   []string
	RedirectURIs             []string
	SignGQ                   bool
	issuer                   string
	server                   *http.Server
	publicKeyFinder          discover.PublicKeyFinder
	requestTokenOverrideFunc func(string) ([]byte, error)
	httpSessionHook          http.HandlerFunc
}

func GetDefaultGoogleOpOptions() *Options {
	return &Options{
		Issuer: googleIssuer,

		ClientID: "992028499768-ce9juclb3vvckh23r83fjkmvf1lvjq18.apps.googleusercontent.com",
		// The clientSecret was intentionally checked in. It holds no power. Do not report as a security issue
		// Google requires a ClientSecret even if this a public OIDC App
		ClientSecret: "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", // The client secret is a public value
		Scopes:       []string{"openid profile email"},
		RedirectURIs: []string{
			"http://localhost:3000/login-callback",
			"http://localhost:10001/login-callback",
			"http://localhost:11110/login-callback",
		},
		SignGQ: false,
	}
}

// NewGoogleOp creates a Google OP (OpenID Provider) using the
// default configurations options. It uses the OIDC Relying Party (Client)
// setup by the OpenPubkey project.
func NewGoogleOp() OpenIdProvider {
	options := GetDefaultGoogleOpOptions()
	return NewGoogleOpWithOptions(options)
}

// NewGoogleOpWithOptions creates a Google OP with configuration specified
// using an options struct. This is useful if you want to use your own OIDC
// Client or override the configuration.
func NewGoogleOpWithOptions(opts *Options) OpenIdProvider {
	return &GoogleOp{
		ClientID:                 opts.ClientID,
		ClientSecret:             opts.ClientSecret,
		Scopes:                   opts.Scopes,
		RedirectURIs:             opts.RedirectURIs,
		SignGQ:                   opts.SignGQ,
		issuer:                   opts.Issuer,
		requestTokenOverrideFunc: nil,
		publicKeyFinder:          *discover.DefaultPubkeyFinder(),
	}
}

var _ OpenIdProvider = (*GoogleOp)(nil)
var _ BrowserOpenIdProvider = (*GoogleOp)(nil)

func (g *GoogleOp) requestTokens(ctx context.Context, cicHash string) ([]byte, error) {
	if g.requestTokenOverrideFunc != nil {
		return g.requestTokenOverrideFunc(cicHash)
	}

	redirectURI, ln, err := FindAvaliablePort(g.RedirectURIs)
	if err != nil {
		return nil, err
	}
	logrus.Infof("listening on http://%s/", ln.Addr().String())
	logrus.Info("press ctrl+c to stop")

	g.server = &http.Server{}
	go func() {
		err := g.server.Serve(ln)
		if err != nil && err != http.ErrServerClosed {
			logrus.Error(err)
		}
	}()
	cookieHandler :=
		httphelper.NewCookieHandler(key, key, httphelper.WithUnsecure())
	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(
			rp.WithIssuedAtOffset(issuedAtOffset), rp.WithNonce(
				func(ctx context.Context) string { return cicHash })),
	}
	options = append(options, rp.WithPKCE(cookieHandler))

	provider, err := rp.NewRelyingPartyOIDC(
		googleIssuer, g.ClientID, g.ClientSecret, redirectURI.String(),
		g.Scopes, options...)
	if err != nil {
		return nil, fmt.Errorf("error creating provider: %w", err)
	}

	state := func() string {
		return uuid.New().String()
	}

	ch := make(chan []byte, 1)
	chErr := make(chan error, 1)

	http.Handle("/login", rp.AuthURLHandler(state, provider,
		rp.WithURLParam("nonce", cicHash),
		// Select account requires that the user click the account they want to use.
		// Results in better UX than just automatically dropping them into their
		// only signed in account.
		// See prompt parameter in OIDC spec https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
		rp.WithPromptURLParam("select_account")))

	marshalToken := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty) {
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			chErr <- err
			return
		}

		ch <- []byte(tokens.IDToken)

		// If defined the OIDC client hands over control of the HTTP server session to the OpenPubkey client.
		// Useful for redirecting the user's browser window that just finished OIDC Auth flow to the
		// MFA Cosigner Auth URI.
		if g.httpSessionHook != nil {
			g.httpSessionHook(w, r)
			defer g.server.Shutdown(ctx) // If no http session hook is set, we do server shutdown in RequestTokens
		} else {
			w.Write([]byte("You may now close this window"))
		}
	}

	callbackPath := redirectURI.Path
	http.Handle(callbackPath, rp.CodeExchangeHandler(marshalToken, provider))

	go func() {
		err := g.server.Serve(ln)
		if err != nil && err != http.ErrServerClosed {
			logrus.Error(err)
		}
	}()

	loginURI := fmt.Sprintf("http://localhost:%s/login", redirectURI.Port())
	logrus.Infof("Opening browser to on http://%s/", loginURI)
	util.OpenUrl(loginURI)

	// If httpSessionHook is not defined shutdown the server when done,
	// otherwise keep it open for the httpSessionHook
	// If httpSessionHook is set we handle both possible cases to ensure
	// the server is shutdown:
	// 1. We shut it down if an error occurs in the marshalToken handler
	// 2. We shut it down if the marshalToken handler completes
	if g.httpSessionHook == nil {
		defer g.server.Shutdown(ctx)
	}
	select {
	case err := <-chErr:
		if g.httpSessionHook != nil {
			defer g.server.Shutdown(ctx)
		}
		return nil, err
	case token := <-ch:
		return token, nil
	}
}

func (g *GoogleOp) RequestTokens(ctx context.Context, cic *clientinstance.Claims) ([]byte, error) {
	// Define our commitment as the hash of the client instance claims
	cicHash, err := cic.Hash()
	if err != nil {
		return nil, fmt.Errorf("error calculating client instance claim commitment: %w", err)
	}
	idToken, err := g.requestTokens(ctx, string(cicHash))
	if err != nil {
		return nil, err
	}
	if g.SignGQ {
		return CreateGQToken(ctx, idToken, g)
	}
	return idToken, nil
}

func (g *GoogleOp) PublicKeyByToken(ctx context.Context, token []byte) (*discover.PublicKeyRecord, error) {
	return g.publicKeyFinder.ByToken(ctx, g.issuer, token)
}

func (g *GoogleOp) PublicKeyByKeyId(ctx context.Context, keyID string) (*discover.PublicKeyRecord, error) {
	return g.publicKeyFinder.ByKeyID(ctx, g.issuer, keyID)
}

func (g *GoogleOp) PublicKeyByJTK(ctx context.Context, jtk string) (*discover.PublicKeyRecord, error) {
	return g.publicKeyFinder.ByJTK(ctx, g.issuer, jtk)
}

func (g *GoogleOp) Issuer() string {
	return g.issuer
}

func (g *GoogleOp) VerifyProvider(ctx context.Context, idt []byte, cic *clientinstance.Claims) error {
	vp := NewProviderVerifier(googleIssuer, ProviderVerifierOpts{CommitType: CommitTypesEnum.NONCE_CLAIM, ClientID: g.ClientID})
	return vp.VerifyProvider(ctx, idt, cic)
}

// HookHTTPSession provides a means to hook the HTTP Server session resulting
// from the OpenID Provider sending an authcode to the OIDC client by
// redirecting the user's browser with the authcode supplied in the URI.
// If this hook is set, it will be called after the receiving the authcode
// but before send an HTTP response to the user. The code which sets this hook
// can choose what HTTP response to server to the user.
//
// We use this so that we can redirect the user web browser window to
// the MFA Cosigner URI after the user finishes the OIDC Auth flow. This
// method is only available to browser based providers.
func (g *GoogleOp) HookHTTPSession(h http.HandlerFunc) {
	g.httpSessionHook = h
}

// FindAvaliablePort attempts to open a listener on localhost until it finds one or runs out of redirectURIs to try
func FindAvaliablePort(redirectURIs []string) (*url.URL, net.Listener, error) {
	var ln net.Listener
	var lnErr error
	for _, v := range redirectURIs {
		redirectURI, err := url.Parse(v)
		if err != nil {
			return nil, nil, fmt.Errorf("malformed redirectURI specified, redirectURI was %s", v)
		}

		lnStr := fmt.Sprintf("localhost:%s", redirectURI.Port())
		ln, lnErr = net.Listen("tcp", lnStr)
		if lnErr == nil {
			return redirectURI, ln, nil
		}
	}
	return nil, nil, fmt.Errorf("failed to start a listener for the callback from Google, got %w", lnErr)
}
