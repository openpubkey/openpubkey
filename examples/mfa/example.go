package main

import (
	"context"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/client/providers"
	"github.com/openpubkey/openpubkey/cosigner/cosclient"
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

// func main() {
// 	clientKey, err := util.GenKeyPair(jwa.ES256)
// 	if err != nil {
// 		fmt.Println("error generating key pair:", err)
// 		return
// 	}

// 	provider := &providers.GoogleOp{
// 		ClientID:     clientID,
// 		ClientSecret: clientSecret,
// 		Issuer:       issuer,
// 		Scopes:       scopes,
// 		RedirURIPort: redirURIPort,
// 		CallbackPath: callbackPath,
// 		RedirectURI:  redirectURI,
// 	}

// 	command := os.Args[1]
// 	switch command {
// 	case "login":
// 		opk := &client.OpkClient{
// 			Op: provider,
// 		}

// 		pkt, err := opk.OidcAuth(context.TODO(), clientKey, jwa.ES256, map[string]any{}, false)
// 		if err != nil {
// 			fmt.Println("error generating key pair: ", err)
// 			return
// 		}
// 		fmt.Println("New PK token generated")

// 		// Verify our pktoken including the cosigner signature
// 		if err := client.VerifyPKToken(context.TODO(), pkt, provider); err != nil {
// 			fmt.Println("failed to verify PK token:", err)
// 		}

// 		pktJson, err := json.Marshal(pkt)
// 		if err != nil {
// 			fmt.Println("error serializing pktJson: ", err)
// 			return
// 		}
// 		fmt.Println(string(pktJson))

// 	case "mfa":
// 		rpID := "localhost"
// 		serverUri := "http://localhost:3003"
// 		rpOrigin := "http://localhost:3003"
// 		rpDisplayName := "OpenPubkey"
// 		_, err := webauthn.New(serverUri, rpID, rpOrigin, rpDisplayName)
// 		if err != nil {
// 			fmt.Println("error starting mfa server: ", err)
// 			return
// 		}

// 	default:
// 		fmt.Println("Unrecognized command:", command)
// 	}
// }

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

	cosClient := &cosclient.AuthCosignerClient{
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
			Op:     provider,
			MfaCos: cosClient,
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
		// TODO: Use this to test cosigner signature issuer allow list
		if err := client.VerifyPKToken(context.TODO(), pkt, provider); err != nil {
			fmt.Println("failed to verify PK token:", err)
		}
		if err := pkt.VerifyCosignerSignature(); err != nil {
			fmt.Println("failed to verify PK token cosigner signature:", err)
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
