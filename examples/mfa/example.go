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
	"github.com/openpubkey/openpubkey/cosigner"
	"github.com/openpubkey/openpubkey/examples/mfa/mfacosigner"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/verifier"
)

func main() {
	provider := providers.NewGoogleOp()

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
		)
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
		cosVerifier := cosigner.NewCosignerVerifier(cosignerProvider.Issuer, cosigner.CosignerVerifierOpts{})
		verifier, err := verifier.New(provider, verifier.WithCosignerVerifiers(cosVerifier))
		if err != nil {
			fmt.Println(err)
			return
		}
		if err := verifier.VerifyPKToken(context.TODO(), pkt); err != nil {
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
