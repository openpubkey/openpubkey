package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/client/providers"
	"github.com/openpubkey/openpubkey/cosigner/mfa"
	"github.com/openpubkey/openpubkey/examples/mfa/jwks"
	"github.com/openpubkey/openpubkey/examples/mfa/webauthn"
	"github.com/openpubkey/openpubkey/util"
)

// Variables for building our google provider
var (
	clientID = "184968138938-g1fddl5tglo7mnlbdak8hbsqhhf79f32.apps.googleusercontent.com"
	// The clientSecret was intentionally checked in for the purposes of this example,. It holds no power. Do not report as a security issue
	clientSecret = "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" // Google requires a ClientSecret even if this a public OIDC App
	scopes       = []string{"openid profile email"}
	redirURIPort = "3000"
	callbackPath = "/login-callback"
	redirectURI  = fmt.Sprintf("http://localhost:%v%v", redirURIPort, callbackPath)
)

func main() {
	clientKey, err := util.GenKeyPair(jwa.ES256)
	if err != nil {
		fmt.Println("error generating key pair:", err)
		return
	}

	provider := &providers.GoogleOp{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		RedirURIPort: redirURIPort,
		CallbackPath: callbackPath,
		RedirectURI:  redirectURI,
	}

	opk := &client.OpkClient{
		Op: provider,
	}

	pkt, err := opk.OidcAuth(context.TODO(), clientKey, jwa.ES256, map[string]any{}, false)
	if err != nil {
		fmt.Println("error generating key pair: ", err)
		return
	}

	fmt.Println("New PK token generated")

	cosigner, err := initCosigner()
	if err != nil {
		fmt.Println("failed to initialize cosigner: ", err)
		return
	}

	if err := cosigner.Cosign(pkt); err != nil {
		fmt.Println("error cosigning:", err)
		return
	}

	fmt.Println("PK token cosigned")

	// Verify our pktoken including the cosigner signature
	if err := client.VerifyPKToken(context.TODO(), pkt, provider); err != nil {
		fmt.Println("failed to verify PK token:", err)
	}

	fmt.Println("PK token verified!")

	pktJson, _ := json.MarshalIndent(pkt, "", "  ")
	fmt.Println(string(pktJson))
}

func initCosigner() (*mfa.Cosigner, error) {
	authenticator, err := webauthn.New()
	if err != nil {
		return nil, err
	}

	// Generate the key pair for our cosigner
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	if err != nil {
		return nil, err
	}

	kid := "test-kid"
	server, err := jwks.NewServer(signer, alg, kid)
	if err != nil {
		return nil, err
	}

	fmt.Println("JWKS hosted at", server.URI()+"/.well-known/jwks.json")

	return mfa.NewCosigner(signer, alg, server.URI(), kid, authenticator)
}
