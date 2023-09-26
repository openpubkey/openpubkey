package parties

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"

	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/sirupsen/logrus"
	"github.com/zitadel/oidc/v2/pkg/client"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	"github.com/zitadel/oidc/v2/pkg/oidc"

	httphelper "github.com/zitadel/oidc/v2/pkg/http"

	"github.com/bastionzero/openpubkey/gq"
	"github.com/bastionzero/openpubkey/pktoken"
	"github.com/bastionzero/openpubkey/util"
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

func (g *GoogleOp) RequestTokens(cicHash string) ([]byte, error) {
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
		return nil, fmt.Errorf("error creating provider %w", err)
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
	openUrl(earl)

	go func() {
		err := g.server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			logrus.Error(err)
		}
	}()

	defer g.server.Shutdown(context.TODO())

	select {
	case err := <-chErr:
		return nil, err
	case token := <-ch:
		return token, nil
	}
}

func (g *GoogleOp) VerifyPKToken(pktJSON []byte, cosPk *ecdsa.PublicKey) (map[string]any, error) {
	pkt, err := pktoken.FromJSON(pktJSON)
	if err != nil {
		return nil, fmt.Errorf("error parsing PK Token: %w", err)
	}

	cicphJSON, err := util.Base64DecodeForJWT(pkt.CicPH)
	if err != nil {
		return nil, err
	}

	nonce := string(util.B64SHA3_256(cicphJSON))

	idt := pkt.OpJWSCompact()
	if pkt.OpSigGQ {
		// TODO: this needs to get the public key from a log of historic public keys based on the iat time in the token
		pubKey, err := g.PublicKey(idt)
		if err != nil {
			return nil, fmt.Errorf("failed to get OP public key: %w", err)
		}
		sv := gq.NewSignerVerifier(pubKey.(*rsa.PublicKey), gqSecurityParameter)
		signingPayload, signature, err := util.SplitJWT(idt)
		if err != nil {
			return nil, fmt.Errorf("failed to split/decode JWT: %w", err)
		}
		ok := sv.Verify(signature, signingPayload, signingPayload)
		if !ok {
			return nil, fmt.Errorf("error verifying OP GQ signature on PK Token (ID Token invalid): %w", err)
		}

		payloadB64 := bytes.Split(signingPayload, []byte{'.'})[1]
		payloadJSON, err := util.Base64DecodeForJWT(payloadB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode header: %w", err)
		}

		var payload map[string]any
		json.Unmarshal(payloadJSON, &payload)
		if payload["nonce"] != nonce {
			return nil, fmt.Errorf("nonce doesn't match")
		}

	} else {
		options := []rp.Option{
			rp.WithVerifierOpts(rp.WithIssuedAtOffset(5*time.Second), rp.WithNonce(func(ctx context.Context) string { return nonce })),
		}

		googleRP, err := rp.NewRelyingPartyOIDC(
			g.Issuer, g.ClientID, g.ClientSecret, g.RedirectURI, g.Scopes,
			options...)

		if err != nil {
			return nil, fmt.Errorf("failed to create RP to verify token: %w", err)
		}

		_, err = rp.VerifyIDToken[*oidc.IDTokenClaims](context.TODO(), string(idt), googleRP.IDTokenVerifier())
		if err != nil {
			return nil, fmt.Errorf("error verifying OP signature on PK Token (ID Token invalid): %w", err)
		}
	}

	err = pkt.VerifyCicSig()
	if err != nil {
		return nil, fmt.Errorf("error verifying CIC signature on PK Token: %w", err)
	}

	// Skip Cosigner signature verification if no cosigner pubkey is supplied
	if cosPk != nil {
		cosPkJwk, err := jwk.FromRaw(cosPk)
		if err != nil {
			return nil, fmt.Errorf("error verifying CIC signature on PK Token: %w", err)
		}

		err = pkt.VerifyCosSig(cosPkJwk, jwa.KeyAlgorithmFrom("ES256"))
		if err != nil {
			return nil, fmt.Errorf("error verify cosigner signature on PK Token: %w", err)
		}
	}

	fmt.Println("All tests have passed PK Token is valid")

	cicPH := make(map[string]any)
	err = json.Unmarshal(cicphJSON, &cicPH)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling CIC: %w", err)
	}

	return cicPH, nil
}

func (g *GoogleOp) PublicKey(idt []byte) (PublicKey, error) {
	j, err := jws.Parse(idt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWS: %w", err)
	}
	kid := j.Signatures()[0].ProtectedHeaders().KeyID()

	discConf, err := client.Discover(g.Issuer, http.DefaultClient)
	if err != nil {
		return nil, fmt.Errorf("failed to call OIDC discovery endpoint: %w", err)
	}

	jwks, err := jwk.Fetch(context.TODO(), discConf.JwksURI)
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
