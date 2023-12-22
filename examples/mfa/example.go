package main

import (
	"context"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/client/providers"
	"github.com/openpubkey/openpubkey/examples/mfa/mfacosigner"
	"github.com/openpubkey/openpubkey/util"
)

var (
	clientID = "184968138938-g1fddl5tglo7mnlbdak8hbsqhhf79f32.apps.googleusercontent.com"
	// The clientSecret was intentionally checked in for the purposes of this example,. It holds no power. Do not report as a security issue
	clientSecret = "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" // Google requires a ClientSecret even if this a public OIDC App
	issuer       = "https://accounts.google.com"
	scopes       = []string{"openid profile email"}
	redirURIPort = "3000"
	callbackPath = "/login-callback"
	redirectURI  = fmt.Sprintf("http://localhost:%v%v", redirURIPort, callbackPath)
)

func main() {

	provider := &providers.GoogleOp{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Issuer:       issuer,
		Scopes:       scopes,
		RedirURIPort: redirURIPort,
		CallbackPath: callbackPath,
		RedirectURI:  redirectURI,
	}

	cosignerProvider := client.CosignerProvider{
		Issuer:       "http://localhost:3003",
		CallbackPath: "/mfacallback",
	}

	if len(os.Args) < 2 {
		fmt.Printf("Example MFA Cosigner: command choices are: login, mfa")
		return
	}

	command := os.Args[1]
	switch command {
	case "login":

		opk := &client.OpkClient{
			Op:   provider,
			CosP: &cosignerProvider,
		}

		clientKey, err := util.GenKeyPair(jwa.ES256)
		if err != nil {
			fmt.Println("error generating key pair:", err)
			return
		}

		pkt, err := opk.Auth(context.TODO(), clientKey, jwa.ES256, map[string]any{}, false)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("New PK token generated")

		// Verify our pktoken including the cosigner signature
		if err := client.VerifyPKToken(context.TODO(), pkt, provider); err != nil {
			fmt.Println("failed to verify PK token:", err)
		}
		// TODO: This is not secure because it does not check that issuer is the expected issuer
		// This will be addressed in https://github.com/openpubkey/openpubkey/pull/72
		if err := pkt.VerifyCosignerSignature(); err != nil {
			fmt.Println("failed to verify PK token cosigner signature:", err)
		}

		os.Exit(0)
	case "mfa":
		rpID := "localhost"
		serverUri := "http://localhost:3003"
		rpOrigin := "http://localhost:3003"
		rpDisplayName := "OpenPubkey"
		_, err := mfacosigner.NewMfaCosignerHttpServer(serverUri, rpID, rpOrigin, rpDisplayName)
		if err != nil {
			fmt.Println("error starting mfa server: ", err)
			return
		}

	default:
		fmt.Println("Unrecognized command:", command)
		fmt.Printf("Example MFA Cosigner: command choices are: login, mfa")
	}
}
