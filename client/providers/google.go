package providers

import (
	"context"
	"crypto"
	"fmt"
	"net/http"

	"time"

	"github.com/awnumar/memguard"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/util"
	"github.com/sirupsen/logrus"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	"github.com/zitadel/oidc/v2/pkg/oidc"

	httphelper "github.com/zitadel/oidc/v2/pkg/http"
)

var (
	key = []byte("NotASecureKey123")
)

const googleIssuer = "https://accounts.google.com"

type GoogleOp struct {
	ClientID     string
	ClientSecret string
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
		g.Issuer(), g.ClientID, g.ClientSecret, g.RedirectURI,
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

func (g *GoogleOp) Issuer() string {
	return googleIssuer
}

func (g *GoogleOp) PublicKey(ctx context.Context, headers jws.Headers) (crypto.PublicKey, error) {
	return client.DiscoverPublicKey(ctx, headers, googleIssuer)
}

func (g *GoogleOp) VerifyNonGQSig(ctx context.Context, idt []byte, expectedNonce string) error {
	options := []rp.Option{
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5*time.Second), rp.WithNonce(func(ctx context.Context) string { return expectedNonce })),
	}

	googleRP, err := rp.NewRelyingPartyOIDC(
		googleIssuer, g.ClientID, g.ClientSecret, g.RedirectURI, g.Scopes,
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
