package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/client/providers"
	"github.com/openpubkey/openpubkey/examples/mfa/webauthn"
	"github.com/openpubkey/openpubkey/util"
)

// Variables for building our google provider
// var (
// 	clientID = "184968138938-g1fddl5tglo7mnlbdak8hbsqhhf79f32.apps.googleusercontent.com"
// 	// The clientSecret was intentionally checked in for the purposes of this example,. It holds no power. Do not report as a security issue
// 	clientSecret = "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" // Google requires a ClientSecret even if this a public OIDC App
// 	issuer       = "https://accounts.google.com"
// 	scopes       = []string{"openid profile email"}
// 	redirURIPort = "3000"
// 	callbackPath = "/login-callback"
// 	redirectURI  = fmt.Sprintf("http://localhost:%v%v", redirURIPort, callbackPath)
// )

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
	clientKey, err := util.GenKeyPair(jwa.ES256)
	if err != nil {
		fmt.Println("error generating key pair:", err)
		return
	}

	provider := &providers.GoogleOp{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Issuer:       issuer,
		Scopes:       scopes,
		RedirURIPort: redirURIPort,
		CallbackPath: callbackPath,
		RedirectURI:  redirectURI,
	}

	command := os.Args[1]
	switch command {
	case "login":
		opk := &client.OpkClient{
			Op: provider,
		}

		pkt, err := opk.OidcAuth(context.TODO(), clientKey, jwa.ES256, map[string]any{}, false)
		if err != nil {
			fmt.Println("error generating key pair: ", err)
			return
		}
		fmt.Println("New PK token generated")

		// Verify our pktoken including the cosigner signature
		if err := client.VerifyPKToken(context.TODO(), pkt, provider); err != nil {
			fmt.Println("failed to verify PK token:", err)
		}

		pktJson, err := json.Marshal(pkt)
		if err != nil {
			fmt.Println("error serializing pktJson: ", err)
			return
		}
		fmt.Println(string(pktJson))

	case "mfa":

		_, err := webauthn.New()
		if err != nil {
			fmt.Println("error starting mfa server: ", err)
			return
		}

	default:
		fmt.Println("Unrecognized command:", command)
	}

}
