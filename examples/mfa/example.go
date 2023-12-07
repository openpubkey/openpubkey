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
	clientID = "115045953232-9e3co450v3dagfh5q8pplip4otb5bgim.apps.googleusercontent.com"
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
		Issuer:      "http://localhost:3003",
		RedirectURI: "http://localhost:3000/mfacallback",
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
			CosP: cosignerProvider,
		}

		clientKey, err := util.GenKeyPair(jwa.ES256)
		if err != nil {
			fmt.Println("error generating key pair:", err)
			return
		}

		pkt, err := opk.CosAuth(context.TODO(), clientKey, jwa.ES256, map[string]any{}, false)
		if err != nil {
			fmt.Println("error generating key pair: ", err)
			return
		}
		fmt.Println("New PK token generated")

		// Verify our pktoken including the cosigner signature
		err = client.PKTokenVerifer{
			AllowedProviders: []client.OpenIdProvider{provider},
			AllowedCosigners: []client.CosignerProvider{cosignerProvider},
		}.Verify(context.TODO(), pkt)
		if err != nil {
			fmt.Println("failed to verify PK token:", err)
		} else {
			fmt.Println("Verified PK token cosigner signature!")
		}

		os.Exit(0)
	case "mfa":
		rpID := "localhost"
		serverUri := "http://localhost:3003"
		rpOrigin := "http://localhost:3003"
		rpDisplayName := "OpenPubkey"
		_, err := mfacosigner.New(serverUri, rpID, rpOrigin, rpDisplayName)
		if err != nil {
			fmt.Println("error starting mfa server: ", err)
			return
		}

	default:
		fmt.Println("Unrecognized command:", command)
		fmt.Printf("Example MFA Cosigner: command choices are: login, mfa")
	}

}
