// Copyright 2025 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
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
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/client/choosers"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/verifier"
)

func main() {

	if err := login(); err != nil {
		fmt.Println("Error logging in:", err)
	} else {
		fmt.Println("Login successful!")
	}

}

func login() error {
	// Note that Google, Azure will fail as they do not support a nonce in the device flow.
	// Only Hello OP includes the nonce in the ID Tokens and supports device flow with OpenPubkey at this time.

	googleOpOptions := providers.GetDefaultGoogleOpOptions()
	googleOpOptions.DeviceFlow = true
	// We have to use a different client ID/secret for device flow as the standard one is tied to auth code flow.
	googleOpOptions.ClientID = "206584157355-jko5mcefacgl3m7q2urpauoi8s2elfcl.apps.googleusercontent.com"
	googleOpOptions.ClientSecret = "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" // This is a public test client secret (do not report)
	googleOpOptions.GQSign = false
	googleOp := providers.NewGoogleOpWithOptions(googleOpOptions)

	azureOpOptions := providers.GetDefaultAzureOpOptions()
	azureOpOptions.GQSign = false
	azureOpOptions.DeviceFlow = true
	azureOp := providers.NewAzureOpWithOptions(azureOpOptions)

	helloOpOptions := providers.GetDefaultHelloOpOptions()
	helloOpOptions.GQSign = false
	// We have to use a different client ID/secret for device flow as the standard one is tied to auth code flow.
	helloOpOptions.ClientID = "app_fzr7iWr50CWQkGDrLCZBYQc4_2Ak"
	helloOpOptions.DeviceFlow = true
	helloOp := providers.NewHelloOpWithOptions(helloOpOptions)

	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Printf("Received shutdown signal, exiting... %v\n", sigs)
		cancel()
	}()

	openBrowser := true
	op, err := choosers.NewWebChooser(
		// gitlab excluded because it doesn't support device flow
		[]providers.BrowserOpenIdProvider{googleOp, azureOp, helloOp},
		openBrowser,
	).ChooseOp(ctx)
	if err != nil {
		return err
	}

	opkClient, err := client.New(op, client.WithPrintPKToken())
	if err != nil {
		return err
	}

	pkt, err := opkClient.Auth(ctx,
		client.WithExtraClaim("extra", "yes"))
	if err != nil {
		return err
	}

	// Pretty print our json token
	pktJson, err := json.MarshalIndent(pkt, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(pktJson))
	pktCom, err := pkt.Compact()
	if err != nil {
		return err
	}
	fmt.Println("Compact", len(pktCom), string(pktCom))

	if opkClient.Op != helloOp {
		newPkt, err := opkClient.Refresh(ctx)
		if err != nil {
			return err
		}
		fmt.Println("refreshed ID Token", string(newPkt.FreshIDToken))

		// Verify that PK Token is issued by the OP you wish to use and that it has a refreshed ID Token
		ops := []verifier.ProviderVerifier{googleOp, azureOp}
		pktVerifier, err := verifier.NewFromMany(ops, verifier.RequireRefreshedIDToken())
		if err != nil {
			return err
		}
		err = pktVerifier.VerifyPKToken(context.Background(), newPkt)
		if err != nil {
			return err
		}
	} else {
		// HelloOP does not support refresh tokens
		fmt.Println("skipping ID Token refresh for Hello OP as it does not support refresh tokens")

		ops := []verifier.ProviderVerifier{googleOp, azureOp, helloOp}
		pktVerifier, err := verifier.NewFromMany(ops)
		if err != nil {
			return err
		}
		err = pktVerifier.VerifyPKToken(context.Background(), pkt)
		if err != nil {
			return err
		}
	}
	return nil
}
