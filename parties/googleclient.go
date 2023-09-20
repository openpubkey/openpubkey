package parties

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"

	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/sirupsen/logrus"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	"github.com/zitadel/oidc/v2/pkg/oidc"

	httphelper "github.com/zitadel/oidc/v2/pkg/http"

	"github.com/bastionzero/openpubkey/pktoken"
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

func (g *GoogleOp) RequestTokens(cicHash string, cb TokenCallback) error {
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
		logrus.Fatalf("error creating provider %s", err.Error())
	}

	state := func() string {
		return uuid.New().String()
	}

	http.Handle("/login", rp.AuthURLHandler(state, provider, rp.WithURLParam("nonce", cicHash)))

	marshalToken := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty) {
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		cb(tokens)

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
	openUrl(earl)
	logrus.Fatal(g.server.ListenAndServe())

	return nil
}

func (g *GoogleOp) VerifyPKToken(pktCom []byte, cosPk *ecdsa.PublicKey) error {

	pkt, err := pktoken.FromCompact(pktCom)
	if err != nil {
		logrus.Fatalf("Error parsing PK Token: %s", err.Error())
		return err
	}

	nonce, err := pkt.GetNonce()
	if err != nil {
		logrus.Fatalf("Error parsing PK Token: %s", err.Error())
		return err
	}

	options := []rp.Option{
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5*time.Second), rp.WithNonce(func(ctx context.Context) string { return string(nonce) })),
	}

	googleRP, err := rp.NewRelyingPartyOIDC(
		g.Issuer, g.ClientID, g.ClientSecret, g.RedirectURI, g.Scopes,
		options...)

	if err != nil {
		logrus.Fatalf("Failed to create RP to verify token: %s", err.Error())
		return err
	}

	idt := string(pkt.OpJWSCompact())
	_, err = rp.VerifyIDToken[*oidc.IDTokenClaims](context.TODO(), idt, googleRP.IDTokenVerifier())
	if err != nil {
		logrus.Fatalf("Error verifying OP signature on PK Token (ID Token invalid): %s", err.Error())
		return err
	}

	err = pkt.VerifyCicSig()
	if err != nil {
		logrus.Fatalf("Error verifying CIC signature on PK Token: %s", err.Error())
		return err
	}

	// Skip Cosigner signature verification if no cosigner pubkey is supplied
	if cosPk != nil {
		cosPkJwk, err := jwk.FromRaw(cosPk)
		if err != nil {
			logrus.Fatalf("Error verifying CIC signature on PK Token: %s", err.Error())
			return err
		}

		err = pkt.VerifyCosSig(cosPkJwk, jwa.KeyAlgorithmFrom("ES256"))
		if err != nil {
			logrus.Fatalf("Error verify cosigner signature on PK Token: %s", err.Error())
			return err
		}
	}

	fmt.Println("All tests have passed PK Token is valid")
	return nil
}

// https://stackoverflow.com/questions/39320371/how-start-web-server-to-open-page-in-browser-in-golang
// open opens the specified URL in the default browser of the user.
func openUrl(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start"}
	case "darwin":
		cmd = "open"
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
	}
	args = append(args, url)
	return exec.Command(cmd, args...).Start()
}
