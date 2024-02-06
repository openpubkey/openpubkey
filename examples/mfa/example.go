// Copyright 2024 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/client/providers"
	"github.com/openpubkey/openpubkey/examples/mfa/mfacosigner"
)

var (
	clientID = "992028499768-ce9juclb3vvckh23r83fjkmvf1lvjq18.apps.googleusercontent.com"
	// The clientSecret was intentionally checked in. It holds no power and is used for development. Do not report as a security issue
	clientSecret = "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" // Google requires a ClientSecret even if this a public OIDC App
	scopes       = []string{"openid profile email"}
	redirURIPort = "3000"
	callbackPath = "/login-callback"
	redirectURI  = fmt.Sprintf("http://localhost:%v%v", redirURIPort, callbackPath)
)

func main() {

	provider := &providers.GoogleOp{
		ClientID:     clientID,
		ClientSecret: clientSecret,
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

		opk, err := client.New(provider,
			client.WithCosignerProvider(&cosignerProvider),
			client.WithSignGQ(false))
		if err != nil {
			fmt.Println(err)
			return
		}

		pkt, err := opk.Auth(context.TODO())
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("New PK token generated")

		// Verify our pktoken including the cosigner signature
		verifier := client.PKTokenVerifier{
			AllowedProviders: []client.OpenIdProvider{provider},
			AllowedCosigners: []client.CosignerProvider{cosignerProvider},
		}

		// Verify our pktoken including the cosigner signature
		if err := verifier.Verify(context.TODO(), pkt); err != nil {
			fmt.Println("Failed to verify PK token:", err)
			os.Exit(1)
		} else {
			fmt.Println("PK token verified successfully!")
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
