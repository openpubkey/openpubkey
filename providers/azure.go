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
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/openpubkey/openpubkey/discover"
	simpleoidc "github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/util"
	"github.com/sirupsen/logrus"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// GoogleOptions is an options struct that configures how providers.GoogleOp
// operates. See providers.GetDefaultGoogleOpOptions for the recommended default
// values to use when interacting with Google as the OpenIdProvider.
type AzureOptions struct {
	// ClientID is the client ID of the OIDC application. It should be the
	// expected "aud" claim in received ID tokens from the OP.
	ClientID string
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
	// TenantID is the GUID  of the Azure tenant/organization. Azure has a
	// different issuer URI for each tenant. Users that are not part of Azure
	// organization, which microsoft nicknames consumers have a default
	// tenant ID of "9188040d-6c67-4c5b-b112-36a304b66dad"
	// More details can be found at
	// https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens
	TenantID string
}

type AzureOp struct {
	ClientID                  string
	ClientSecret              string
	Scopes                    []string
	RedirectURIs              []string
	GQSign                    bool
	OpenBrowser               bool
	HttpClient                *http.Client
	IssuedAtOffset            time.Duration
	TenantID                  string
	issuer                    string
	server                    *http.Server
	publicKeyFinder           discover.PublicKeyFinder
	requestTokensOverrideFunc func(string) (*simpleoidc.Tokens, error)
	httpSessionHook           http.HandlerFunc
}

func GetDefaultAzureOpOptions() *AzureOptions {
	defaultTenantID := "9188040d-6c67-4c5b-b112-36a304b66dad"
	return &AzureOptions{
		Issuer:   azureIssuer(defaultTenantID),
		ClientID: "bd345b9c-6902-400d-9e18-45abdf0f698f", // TODO: replace with a better client ID

		Scopes: []string{"openid profile email", "offline_access"}, // offline_access is required for refresh tokens
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

// NewAzureOp creates a Azure OP (OpenID Provider) using the
// default configurations options. It uses the OIDC Relying Party (Client)
// setup by the OpenPubkey project.
func NewAzureOp() OpenIdProvider {
	options := GetDefaultAzureOpOptions()
	return NewAzureOpWithOptions(options)
}

// NewAzureOpWithOptions creates a Google OP with configuration specified
// using an options struct. This is useful if you want to use your own OIDC
// Client or override the configuration.
func NewAzureOpWithOptions(opts *AzureOptions) *AzureOp {
	return &AzureOp{
		ClientID:                  opts.ClientID,
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

var _ OpenIdProvider = (*AzureOp)(nil)
var _ BrowserOpenIdProvider = (*AzureOp)(nil)
var _ RefreshableOpenIdProvider = (*AzureOp)(nil)

func (a *AzureOp) requestTokens(ctx context.Context, cicHash string) (*simpleoidc.Tokens, error) {
	if a.requestTokensOverrideFunc != nil {
		return a.requestTokensOverrideFunc(cicHash)
	}

	redirectURI, ln, err := FindAvailablePort(a.RedirectURIs)
	if err != nil {
		return nil, err
	}
	logrus.Infof("listening on http://%s/", ln.Addr().String())
	logrus.Info("press ctrl+c to stop")

	mux := http.NewServeMux()
	a.server = &http.Server{Handler: mux}

	// TODO: Do we need these cookies for Azure?
	cookieHandler, err := configCookieHandler()
	if err != nil {
		return nil, err
	}

	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(
			rp.WithIssuedAtOffset(a.IssuedAtOffset), rp.WithNonce(
				func(ctx context.Context) string { return cicHash })),
	}
	options = append(options, rp.WithPKCE(cookieHandler))
	if a.HttpClient != nil {
		options = append(options, rp.WithHTTPClient(a.HttpClient))
	}

	noClientSecret := ""

	// The reason we don't set the relyingParty on the struct and reuse it,
	// is because refresh requests require a slightly different set of
	// options. For instance we want the option to check the nonce (WithNonce)
	// here, but in RefreshTokens we don't want that option set because
	// a refreshed ID token doesn't have a nonce.
	relyingParty, err := rp.NewRelyingPartyOIDC(ctx,
		a.issuer, a.ClientID, noClientSecret, redirectURI.String(), //TODO: no client secret for Azure
		a.Scopes,
		options...)
	if err != nil {
		return nil, fmt.Errorf("error creating provider: %w", err)
	}

	state := func() string {
		return uuid.New().String()
	}

	shutdownServer := func() {
		if err := a.server.Shutdown(ctx); err != nil {
			logrus.Errorf("Failed to shutdown http server: %v", err)
		}
	}

	chTokens := make(chan *oidc.Tokens[*oidc.IDTokenClaims], 1)
	chErr := make(chan error, 1)

	mux.Handle("/login", rp.AuthURLHandler(state, relyingParty,
		rp.WithURLParam("nonce", cicHash),
		// Select account requires that the user click the account they want to use.
		// Results in better UX than just automatically dropping them into their
		// only signed in account.
		// See prompt parameter in OIDC spec https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
		rp.WithPromptURLParam("select_account"),
		rp.WithURLParam("access_type", "offline")),
	)

	marshalToken := func(w http.ResponseWriter, r *http.Request, retTokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty) {
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			chErr <- err
			return
		}

		chTokens <- retTokens

		// If defined the OIDC client hands over control of the HTTP server session to the OpenPubkey client.
		// Useful for redirecting the user's browser window that just finished OIDC Auth flow to the
		// MFA Cosigner Auth URI.
		if a.httpSessionHook != nil {
			a.httpSessionHook(w, r)
			defer shutdownServer() // If no http session hook is set, we do server shutdown in RequestTokens
		} else {
			if _, err := w.Write([]byte("You may now close this window")); err != nil {
				logrus.Error(err)
			}
		}
	}

	callbackPath := redirectURI.Path
	mux.Handle(callbackPath, rp.CodeExchangeHandler(marshalToken, relyingParty))

	go func() {
		err := a.server.Serve(ln)
		if err != nil && err != http.ErrServerClosed {
			logrus.Error(err)
		}
	}()

	if a.OpenBrowser {
		loginURI := fmt.Sprintf("http://localhost:%s/login", redirectURI.Port())
		logrus.Infof("Opening browser to on http://%s/", loginURI)
		if err := util.OpenUrl(loginURI); err != nil {
			logrus.Errorf("Failed to open url: %v", err)
		}
	}

	// If httpSessionHook is not defined shutdown the server when done,
	// otherwise keep it open for the httpSessionHook
	// If httpSessionHook is set we handle both possible cases to ensure
	// the server is shutdown:
	// 1. We shut it down if an error occurs in the marshalToken handler
	// 2. We shut it down if the marshalToken handler completes
	if a.httpSessionHook == nil {
		defer shutdownServer()
	}
	select {
	case err := <-chErr:
		if a.httpSessionHook != nil {
			defer shutdownServer()
		}
		return nil, err
	case retTokens := <-chTokens:
		// retTokens is a zitadel/oidc struct. We turn it into our simpler token struct
		return &simpleoidc.Tokens{
			IDToken:      []byte(retTokens.IDToken),
			RefreshToken: []byte(retTokens.RefreshToken),
			AccessToken:  []byte(retTokens.AccessToken)}, nil
	}
}

func (a *AzureOp) RequestTokens(ctx context.Context, cic *clientinstance.Claims) (*simpleoidc.Tokens, error) {
	// Define our commitment as the hash of the client instance claims
	cicHash, err := cic.Hash()
	if err != nil {
		return nil, fmt.Errorf("error calculating client instance claim commitment: %w", err)
	}
	tokens, err := a.requestTokens(ctx, string(cicHash))
	if err != nil {
		return nil, err
	}
	if a.GQSign {
		idToken := tokens.IDToken
		if gqToken, err := CreateGQToken(ctx, idToken, a); err != nil {
			return nil, err
		} else {
			tokens.IDToken = gqToken
			return tokens, nil
		}
	}
	return tokens, nil
}

func (a *AzureOp) RefreshTokens(ctx context.Context, refreshToken []byte) (*simpleoidc.Tokens, error) {
	cookieHandler, err := configCookieHandler()
	if err != nil {
		return nil, err
	}
	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(
			rp.WithIssuedAtOffset(a.IssuedAtOffset),
			rp.WithNonce(nil), // disable nonce check
		),
	}
	options = append(options, rp.WithPKCE(cookieHandler))
	if a.HttpClient != nil {
		options = append(options, rp.WithHTTPClient(a.HttpClient))
	}

	// The redirect URI is not sent in the refresh request so we set it to an empty string.
	// According to the OIDC spec the only values send on a refresh request are:
	// client_id, client_secret, grant_type, refresh_token, and scope.
	// https://openid.net/specs/openid-connect-core-1_0.html#RefreshingAccessToken
	redirectURI := ""
	noClientSecret := ""
	relyingParty, err := rp.NewRelyingPartyOIDC(ctx, a.issuer, a.ClientID,
		noClientSecret, redirectURI, a.Scopes, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to create RP to verify token: %w", err)
	}
	retTokens, err := rp.RefreshTokens[*oidc.IDTokenClaims](ctx, relyingParty, string(refreshToken), "", "")
	if err != nil {
		return nil, err
	}

	if retTokens.RefreshToken == "" {
		// Google does not rotate refresh tokens, the one you get at the
		// beginning is the only one you'll ever get
		retTokens.RefreshToken = string(refreshToken)
	}

	return &simpleoidc.Tokens{
		IDToken:      []byte(retTokens.IDToken),
		RefreshToken: []byte(retTokens.RefreshToken),
		AccessToken:  []byte(retTokens.AccessToken)}, nil
}

func (a *AzureOp) PublicKeyByToken(ctx context.Context, token []byte) (*discover.PublicKeyRecord, error) {
	return a.publicKeyFinder.ByToken(ctx, a.issuer, token)
}

func (a *AzureOp) PublicKeyByKeyId(ctx context.Context, keyID string) (*discover.PublicKeyRecord, error) {
	return a.publicKeyFinder.ByKeyID(ctx, a.issuer, keyID)
}

func (a *AzureOp) Issuer() string {
	return a.issuer
}

func (a *AzureOp) VerifyIDToken(ctx context.Context, idt []byte, cic *clientinstance.Claims) error {
	vp := NewProviderVerifier(a.issuer, ProviderVerifierOpts{CommitType: CommitTypesEnum.NONCE_CLAIM, ClientID: a.ClientID, DiscoverPublicKey: &a.publicKeyFinder})
	return vp.VerifyIDToken(ctx, idt, cic)
}

func (a *AzureOp) VerifyRefreshedIDToken(ctx context.Context, origIdt []byte, reIdt []byte) error {
	if err := simpleoidc.SameIdentity(origIdt, reIdt); err != nil {
		return fmt.Errorf("refreshed ID Token is for different subject than original ID Token: %w", err)
	}
	if err := simpleoidc.RequireOlder(origIdt, reIdt); err != nil {
		return fmt.Errorf("refreshed ID Token should not be issued before original ID Token: %w", err)
	}

	options := []rp.Option{}
	if a.HttpClient != nil {
		options = append(options, rp.WithHTTPClient(a.HttpClient))
	}
	redirectURI := ""
	noClientSecret := ""
	relyingParty, err := rp.NewRelyingPartyOIDC(ctx, a.issuer, a.ClientID,
		noClientSecret, redirectURI, a.Scopes, options...)
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
func (a *AzureOp) HookHTTPSession(h http.HandlerFunc) {
	a.httpSessionHook = h
}

func azureIssuer(tenantID string) string {
	return fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenantID)
}
