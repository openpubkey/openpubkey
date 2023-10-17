package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/zitadel/oidc/v2/pkg/oidc"

	"github.com/openpubkey/openpubkey/parties"
	"github.com/openpubkey/openpubkey/util"
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
		alg := jwa.ES256
		signGQ := true // are we using gq proofs?

		// Generate a key pair in the form of a crypto.Signer and JWK-formatted public key
		signingKey, err := util.GenKeyPair(alg)
		if err != nil {
			fmt.Printf("failed to generate new ecdsa key pair: %s\n", err)
		}

		jwkKey, err := jwk.PublicKeyOf(signingKey)
		if err != nil {
			fmt.Printf("failed to generate JWK key from ecdsa private key: %s\n", err)
		}
		jwkKey.Set(jwk.AlgorithmKey, alg)

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

		pktJson, err := client.OidcAuth(signingKey, alg, map[string]any{}, signGQ)
		if err != nil {
			panic(err)
		}

		var prettyJSON bytes.Buffer
		if err := json.Indent(&prettyJSON, pktJson, "", "    "); err != nil {
			fmt.Printf("our PK Token doesn't want to be pretty: %s\n", err)
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
