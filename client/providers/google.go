package providers

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"
	"net/http"

	"time"

	"github.com/awnumar/memguard"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/util"
	"github.com/sirupsen/logrus"
	oidcclient "github.com/zitadel/oidc/v2/pkg/client"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	"github.com/zitadel/oidc/v2/pkg/oidc"

	httphelper "github.com/zitadel/oidc/v2/pkg/http"
)

var (
	key = []byte("NotASecureKey123")
)

type GoogleOp struct {
	ClientID     string
	ClientSecret string
	Issuer       string
	Scopes       []string
	RedirURIPort string
	CallbackPath string
	RedirectURI  string
	server       *http.Server
}

var _ client.OpenIdProvider = (*GoogleOp)(nil)

func (g *GoogleOp) RequestTokens(ctx context.Context, cicHash string) (*memguard.LockedBuffer, error) {
	cookieHandler :=
		httphelper.NewCookieHandler(key, key, httphelper.WithUnsecure())
	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(
			rp.WithIssuedAtOffset(5*time.Second), rp.WithNonce(
				func(ctx context.Context) string { return cicHash })),
	}
	options = append(options, rp.WithPKCE(cookieHandler))

	provider, err := rp.NewRelyingPartyOIDC(
		g.Issuer, g.ClientID, g.ClientSecret, g.RedirectURI,
		g.Scopes, options...)
	if err != nil {
		return nil, fmt.Errorf("error creating provider: %w", err)
	}

	state := func() string {
		return uuid.New().String()
	}

	ch := make(chan []byte)
	chErr := make(chan error)

	http.Handle("/login", rp.AuthURLHandler(state, provider, rp.WithURLParam("nonce", cicHash)))

	marshalToken := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty) {
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			chErr <- err
			return
		}

		ch <- []byte(tokens.IDToken)
		w.Write([]byte("You may now close this window"))
	}

	http.Handle(g.CallbackPath, rp.CodeExchangeHandler(marshalToken, provider))

	lis := fmt.Sprintf("localhost:%s", g.RedirURIPort)
	g.server = &http.Server{
		Addr: lis,
	}

	logrus.Infof("listening on http://%s/", lis)
	logrus.Info("press ctrl+c to stop")
	earl := fmt.Sprintf("http://localhost:%s/login", g.RedirURIPort)
	util.OpenUrl(earl)

	go func() {
		err := g.server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			logrus.Error(err)
		}
	}()

	defer g.server.Shutdown(ctx)

	select {
	case err := <-chErr:
		return nil, err
	case token := <-ch:
		return memguard.NewBufferFromBytes(token), nil
	}
}

func (g *GoogleOp) RequestTokensCos(ctx context.Context, cicHash string, oidcEnder client.OidcEnder) (*client.OidcDone, error) {

	cookieHandler :=
		httphelper.NewCookieHandler(key, key, httphelper.WithUnsecure())
	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(
			rp.WithIssuedAtOffset(5*time.Second), rp.WithNonce(
				func(ctx context.Context) string { return cicHash })),
	}
	options = append(options, rp.WithPKCE(cookieHandler))

	provider, err := rp.NewRelyingPartyOIDC(
		g.Issuer, g.ClientID, g.ClientSecret, g.RedirectURI,
		g.Scopes, options...)
	if err != nil {
		return nil, fmt.Errorf("error creating provider: %w", err)
	}

	state := func() string {
		return uuid.New().String()
	}

	ch := make(chan client.OidcDone)
	chErr := make(chan error)

	http.Handle("/login", rp.AuthURLHandler(state, provider, rp.WithURLParam("nonce", cicHash)))
	marshalToken := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty) {
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			chErr <- err
			return
		}

		ch <- client.OidcDone{
			Token: memguard.NewBufferFromBytes([]byte(tokens.IDToken)),
		}

		oidcEnder(w, r)
	}
	http.Handle(g.CallbackPath, rp.CodeExchangeHandler(marshalToken, provider))

	lis := fmt.Sprintf("localhost:%s", g.RedirURIPort)
	g.server = &http.Server{
		Addr: lis,
	}

	logrus.Infof("WWW listening on http://%s/", lis)
	logrus.Info("press ctrl+c to stop")
	earl := fmt.Sprintf("http://localhost:%s/login", g.RedirURIPort)
	util.OpenUrl(earl)

	go func() {
		err := g.server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			logrus.Error(err)
		}
	}()

	// defer g.server.Shutdown(ctx)

	select {
	case err := <-chErr:
		return nil, err
	case oidcDone := <-ch:
		// w := oidcDone.WriteHttp
		// w.Write([]byte("You may now close this window2"))
		return &oidcDone, nil
	}
}

func (g *GoogleOp) VerifyCICHash(ctx context.Context, idt []byte, expectedCICHash string) error {
	cicHash, err := client.ExtractClaim(idt, "nonce")
	if err != nil {
		return err
	}

	if cicHash != expectedCICHash {
		return fmt.Errorf("nonce claim doesn't match, got %q, expected %q", cicHash, expectedCICHash)
	}

	return nil
}

func (g *GoogleOp) PublicKey(ctx context.Context, idt []byte) (crypto.PublicKey, error) {
	j, err := jws.Parse(idt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWS: %w", err)
	}
	kid := j.Signatures()[0].ProtectedHeaders().KeyID()

	discConf, err := oidcclient.Discover(g.Issuer, http.DefaultClient)
	if err != nil {
		return nil, fmt.Errorf("failed to call OIDC discovery endpoint: %w", err)
	}

	jwks, err := jwk.Fetch(ctx, discConf.JwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch to JWKS: %w", err)
	}

	key, ok := jwks.LookupKeyID(kid)
	if !ok {
		return nil, fmt.Errorf("key isn't in JWKS")
	}

	pubKey := new(rsa.PublicKey)
	err = key.Raw(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	return pubKey, err
}

func (g *GoogleOp) VerifyNonGQSig(ctx context.Context, idt []byte, expectedNonce string) error {
	options := []rp.Option{
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5*time.Second), rp.WithNonce(func(ctx context.Context) string { return expectedNonce })),
	}

	googleRP, err := rp.NewRelyingPartyOIDC(
		g.Issuer, g.ClientID, g.ClientSecret, g.RedirectURI, g.Scopes,
		options...)

	if err != nil {
		return fmt.Errorf("failed to create RP to verify token: %w", err)
	}

	_, err = rp.VerifyIDToken[*oidc.IDTokenClaims](ctx, string(idt), googleRP.IDTokenVerifier())
	if err != nil {
		return fmt.Errorf("error verifying OP signature on PK Token (ID Token invalid): %w", err)
	}

	return nil
}
