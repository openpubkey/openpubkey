package parties

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"io"
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

type OpkClient struct {
	PktCom       []byte
	Signer       *pktoken.Signer
	ClientID     string
	ClientSecret string
	Issuer       string
	Scopes       []string
	RedirURIPort string
	CallbackPath string
	RedirectURI  string
	MfaURI       string
	server       *http.Server
}

func (o *OpkClient) RequestCert() ([]byte, error) {
	uri := fmt.Sprintf("http://localhost:3002/cert?pkt=%s", o.PktCom)
	resp, err := http.Get(uri)
	if err != nil {
		fmt.Printf("MFA request failed: %v\n", err)
		return nil, err
	}
	defer resp.Body.Close()

	certBytes, err := io.ReadAll(resp.Body)

	return certBytes, nil
}

func (o *OpkClient) OidcAuth() error {
	nonce := o.Signer.GetNonce()

	receiveIDTHandler := func(tokens *oidc.Tokens[*oidc.IDTokenClaims]) {

	}

	o.PerformGoogleAuthFlow(nonce, receiveIDTHandler)

	return nil
}

type ReceiveIDTHandler func(tokens *oidc.Tokens[*oidc.IDTokenClaims])

func (o *OpkClient) PerformGoogleAuthFlow(nonce string, receiveIDTHandler ReceiveIDTHandler) {

	cookieHandler := httphelper.NewCookieHandler(key, key, httphelper.WithUnsecure())
	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5*time.Second), rp.WithNonce(func(ctx context.Context) string { return nonce })),
	}
	options = append(options, rp.WithPKCE(cookieHandler))

	provider, err := rp.NewRelyingPartyOIDC(o.Issuer, o.ClientID, o.ClientSecret, o.RedirectURI, o.Scopes, options...)
	if err != nil {
		logrus.Fatalf("error creating provider %s", err.Error())
	}

	state := func() string {
		return uuid.New().String()
	}

	http.Handle("/login", rp.AuthURLHandler(state, provider, rp.WithURLParam("nonce", nonce)))

	marshalToken := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty) {
		// data, err := json.Marshal(tokens)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// w.Write(data)

		idt := []byte(tokens.IDToken)
		pkt, err := o.Signer.CreatePkToken(idt)

		if err != nil {
			logrus.Fatalf("Error creating PK Token: %s", err.Error())
			return
		}

		pktCom := pkt.ToCompact()
		fmt.Printf("PKT=%s", pktCom)

		err = o.Signer.WriteToFile(pktCom)
		if err != nil {
			logrus.Fatalf("Error creating PK Token: %s", err.Error())
			return
		}

		w.Write([]byte("You may now close this window"))
	}

	http.Handle(o.CallbackPath, rp.CodeExchangeHandler(marshalToken, provider))

	lis := fmt.Sprintf("localhost:%s", o.RedirURIPort)
	o.server = &http.Server{
		Addr: lis,
	}
	// defer o.server.Close()

	logrus.Infof("listening on http://%s/", lis)
	logrus.Info("press ctrl+c to stop")
	earl := fmt.Sprintf("http://localhost:%s/login", o.RedirURIPort)
	openUrl(earl)
	logrus.Fatal(o.server.ListenAndServe())

}

func (o *OpkClient) VerifyPKToken(pktCom []byte, cosPk *ecdsa.PublicKey) error {

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

	googleRP, err := rp.NewRelyingPartyOIDC(o.Issuer, o.ClientID, o.ClientSecret, o.RedirectURI, o.Scopes, options...)
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
