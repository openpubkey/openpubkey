package main

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/parties"
	"github.com/openpubkey/openpubkey/parties/webauthn"
	"github.com/openpubkey/openpubkey/util"
)

// Variables for building our google provider
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
	cosigner, err := webauthn.New()
	if err != nil {
		fmt.Println("error instantiating cosigner:", err.Error())
		return
	}

	fmt.Println("Cosigner ready, now testing registration")

	signer, err := util.GenKeyPair(jwa.ES256)
	if err != nil {
		fmt.Println("error generating key pair:", err.Error())
		return
	}

	client := &parties.OpkClient{
		Op: &parties.GoogleOp{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Issuer:       issuer,
			Scopes:       scopes,
			RedirURIPort: redirURIPort,
			CallbackPath: callbackPath,
			RedirectURI:  redirectURI,
		},
	}

	pkt, err := client.OidcAuth(signer, jwa.ES256, map[string]any{"extra": "yes"}, false)
	if err != nil {
		fmt.Println("error generating key pair: ", err.Error())
		return
	}

	costoken, err := cosigner.Cosign(pkt)
	if err != nil {
		fmt.Println("error cosigning:", err.Error())
		return
	}

	fmt.Println(costoken)
	select {}
}
