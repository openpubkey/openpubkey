package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/zitadel/oidc/v2/pkg/oidc"

	"github.com/openpubkey/openpubkey/parties"
	"github.com/openpubkey/openpubkey/signer"
)

// TODO: Create nice golang services rather than just using this handler nonsense

type ReceiveIDTHandler func(tokens *oidc.Tokens[*oidc.IDTokenClaims])

func GoogleSign() {}

func GoogleCert() {}

func CaKeyGen() {}

func CaServ() {}

func SigStoreSign() {}

func main() {

	if len(os.Args) < 2 {
		fmt.Printf("OpenPubkey: command required choices are login, sign, cert, cagen, ca")
		return
	}

	command := os.Args[1]

	switch command {
	case "login":
		// Generate user signing key pair
		signer, err := signer.NewECDSASigner()
		if err != nil {
			panic(err)
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
			SigningKey:    signer.SigningKey(),
			UserPublicKey: signer.JWKKey(),
			Gq:            true,
		}

		pktJson, err := client.OidcAuth()
		if err != nil {
			panic(err)
		}

		var prettyJSON bytes.Buffer
		if err := json.Indent(&prettyJSON, pktJson, "", "    "); err != nil {
			panic(fmt.Errorf("our PK Token doesn't want to be pretty: %w", err))
		}
	case "sign":
		GoogleSign()

	case "cert":
		GoogleCert()

	case "cagen":
		CaKeyGen()

	case "ca":
		CaServ()

	case "sss":
		SigStoreSign()

	default:
		fmt.Printf("Unrecognized command: %s", command)
	}
}
