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
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"

	"time"

	"github.com/google/uuid"
	"github.com/openpubkey/openpubkey/discover"
	simpleoidc "github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/util"
	"github.com/sirupsen/logrus"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	httphelper "github.com/zitadel/oidc/v3/pkg/http"
)

var (
	issuedAtOffset = 1 * time.Minute
)

const googleIssuer = "https://accounts.google.com"

type GoogleOptions struct {
	ClientID     string
	ClientSecret string
	Issuer       string // This should almost always be "https://accounts.google.com"
	Scopes       []string
	RedirectURIs []string
	GQSign       bool
}

type GoogleOp struct {
	ClientID                 string
	ClientSecret             string
	Scopes                   []string
	RedirectURIs             []string
	GQSign                   bool
	issuer                   string
	server                   *http.Server
	publicKeyFinder          discover.PublicKeyFinder
	requestTokenOverrideFunc func(string) ([]byte, []byte, []byte, error)
	httpSessionHook          http.HandlerFunc
}

func GetDefaultGoogleOpOptions() *GoogleOptions {
	return &GoogleOptions{
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
		GQSign: false,
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
func NewGoogleOpWithOptions(opts *GoogleOptions) OpenIdProvider {
	return &GoogleOp{
		ClientID:                 opts.ClientID,
		ClientSecret:             opts.ClientSecret,
		Scopes:                   opts.Scopes,
		RedirectURIs:             opts.RedirectURIs,
		GQSign:                   opts.GQSign,
		issuer:                   opts.Issuer,
		requestTokenOverrideFunc: nil,
		publicKeyFinder:          *discover.DefaultPubkeyFinder(),
	}
}

var _ OpenIdProvider = (*GoogleOp)(nil)
var _ BrowserOpenIdProvider = (*GoogleOp)(nil)

func (g *GoogleOp) requestTokens(ctx context.Context, cicHash string) ([]byte, []byte, []byte, error) {
	if g.requestTokenOverrideFunc != nil {
		return g.requestTokenOverrideFunc(cicHash)
	}

	redirectURI, ln, err := FindAvailablePort(g.RedirectURIs)
	if err != nil {
		return nil, nil, nil, err
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

	cookieHandler, err := configCookieHandler()
	if err != nil {
		return nil, nil, nil, err
	}
	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(
			rp.WithIssuedAtOffset(issuedAtOffset), rp.WithNonce(
				func(ctx context.Context) string { return cicHash })),
	}
	options = append(options, rp.WithPKCE(cookieHandler))

	// The reason we don't set the relyingParty on the struct and reuse it,
	// is because refresh requests require a slightly different set of
	// options. For instance we want the option to check the nonce (WithNonce)
	// here, but in RefreshTokens we don't want that option set because
	// a refreshed ID token doesn't have a nonce.
	relyingParty, err := rp.NewRelyingPartyOIDC(ctx,
		g.issuer, g.ClientID, g.ClientSecret, redirectURI.String(),
		g.Scopes, options...)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating provider: %w", err)
	}

	state := func() string {
		return uuid.New().String()
	}

	chTokens := make(chan *oidc.Tokens[*oidc.IDTokenClaims], 1)
	chErr := make(chan error, 1)

	http.Handle("/login", rp.AuthURLHandler(state, relyingParty,
		rp.WithURLParam("nonce", cicHash),
		// Select account requires that the user click the account they want to use.
		// Results in better UX than just automatically dropping them into their
		// only signed in account.
		// See prompt parameter in OIDC spec https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
		rp.WithPromptURLParam("select_account"),
		rp.WithURLParam("access_type", "offline")))

	marshalToken := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty) {
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			chErr <- err
			return
		}

		chTokens <- tokens

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
	http.Handle(callbackPath, rp.CodeExchangeHandler(marshalToken, relyingParty))

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
		return nil, nil, nil, err
	case tokens := <-chTokens:
		return []byte(tokens.IDToken), []byte(tokens.RefreshToken), []byte(tokens.AccessToken), nil
	}
}

func (g *GoogleOp) RequestTokens(ctx context.Context, cic *clientinstance.Claims) ([]byte, []byte, []byte, error) {
	// Define our commitment as the hash of the client instance claims
	cicHash, err := cic.Hash()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error calculating client instance claim commitment: %w", err)
	}
	idToken, refreshToken, accessToken, err := g.requestTokens(ctx, string(cicHash))
	if err != nil {
		return nil, nil, nil, err
	}
	if g.GQSign {
		if gqToken, err := CreateGQToken(ctx, idToken, g); err != nil {
			return nil, nil, nil, err
		} else {
			return gqToken, refreshToken, accessToken, nil
		}
	}
	return idToken, refreshToken, accessToken, nil
}

func (g *GoogleOp) RefreshTokens(ctx context.Context, refreshToken []byte) ([]byte, []byte, []byte, error) {
	cookieHandler, err := configCookieHandler()
	if err != nil {
		return nil, nil, nil, err
	}
	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(
			rp.WithIssuedAtOffset(issuedAtOffset)),
	}
	options = append(options, rp.WithPKCE(cookieHandler))

	// The redirect URI is not sent in the refresh request so we set it to an empty string.
	// According to the OIDC spec the only values send on a refresh request are:
	// client_id, client_secret, grant_type, refresh_token, and scope.
	// https://openid.net/specs/openid-connect-core-1_0.html#RefreshingAccessToken
	redirectURI := ""
	relyingParty, err := rp.NewRelyingPartyOIDC(ctx, g.issuer, g.ClientID,
		g.ClientSecret, redirectURI, g.Scopes, options...)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create RP to verify token: %w", err)
	}
	tokens, err := rp.RefreshTokens[*oidc.IDTokenClaims](ctx, relyingParty, string(refreshToken), "", "")
	if err != nil {
		return nil, nil, nil, err
	}

	return []byte(tokens.IDToken), refreshToken, []byte(tokens.AccessToken), nil
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

func (g *GoogleOp) VerifyIDToken(ctx context.Context, idt []byte, cic *clientinstance.Claims) error {
	vp := NewProviderVerifier(g.issuer, ProviderVerifierOpts{CommitType: CommitTypesEnum.NONCE_CLAIM, ClientID: g.ClientID})
	return vp.VerifyIDToken(ctx, idt, cic)
}

func (g *GoogleOp) VerifyRefreshedIDToken(ctx context.Context, origIdt []byte, reIdt []byte) error {
	if err := simpleoidc.SameIdentity(origIdt, reIdt); err != nil {
		return fmt.Errorf("refreshed ID Token is for different subject than original ID Token: %w", err)
	}
	if err := simpleoidc.RequireOlder(origIdt, reIdt); err != nil {
		return fmt.Errorf("refreshed ID Token should not be issued before original ID Token: %w", err)
	}

	redirectURI := ""
	relyingParty, err := rp.NewRelyingPartyOIDC(ctx, g.issuer, g.ClientID,
		g.ClientSecret, redirectURI, g.Scopes)
	if err != nil {
		return fmt.Errorf("failed to create RP to verify token: %w", err)
	}
	_, err = rp.VerifyIDToken[*oidc.IDTokenClaims](ctx, string(reIdt), relyingParty.IDTokenVerifier())
	return err
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

// FindAvailablePort attempts to open a listener on localhost until it finds one or runs out of redirectURIs to try
func FindAvailablePort(redirectURIs []string) (*url.URL, net.Listener, error) {
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
	return nil, nil, fmt.Errorf("failed to start a listener for the callback from the OP, got %w", lnErr)
}

func configCookieHandler() (*httphelper.CookieHandler, error) {
	// I've been unable to determine a scenario in which setting a hashKey and blockKey
	// on the cookie provide protection in the localhost redirect URI case. However I
	// see no harm in setting it.
	hashKey := make([]byte, 64)
	if _, err := io.ReadFull(rand.Reader, hashKey); err != nil {
		return nil, fmt.Errorf("failed to generate random keys for cookie storage")
	}
	blockKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, blockKey); err != nil {
		return nil, fmt.Errorf("failed to generate random keys for cookie storage")
	}

	// OpenPubkey uses a localhost redirect URI to receive the authcode
	// from the OP. Localhost redirects use http not https. Thus, we should
	// not set these cookies as secure-only. This should be changed if
	// OpenPubkey added support for non-localhost redirect URIs.
	// WithUnsecure() is equivalent to not setting the 'secure' attribute
	// flag in an HTTP Set-Cookie header (see https://http.dev/set-cookie#secure)
	return httphelper.NewCookieHandler(hashKey, blockKey, httphelper.WithUnsecure()), nil
}
