// Copyright 2024 OpenPubkey
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

	"github.com/awnumar/memguard"

	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/examples/x509/ca"
	"github.com/openpubkey/openpubkey/providers"
)

func main() {
	// Safely terminate in case of an interrupt signal
	memguard.CatchInterrupt()

	// Purge the session when we return
	defer memguard.Purge()

	if len(os.Args) < 2 {
		fmt.Printf("OpenPubkey: command choices are login, sign, and cert")
		return
	}

	command := os.Args[1]
	switch command {
	case "login":
		opOpts := providers.GetDefaultGoogleOpOptions()
		opOpts.GQSign = true
		op := providers.NewGoogleOp()
		if err := login(op); err != nil {
			fmt.Println("Error logging in:", err)
		} else {
			fmt.Println("Login and X509 issuance successful!")
		}
	default:
		fmt.Println("Unrecognized command:", command)
	}
}

func login(op client.OpenIdProvider) error {
	opkClient, err := client.New(
		op,
	)
	if err != nil {
		return err
	}

	pkt, err := opkClient.Auth(context.Background())
	if err != nil {
		return err
	}

	// Pretty print our json token
	pktJson, err := json.MarshalIndent(pkt, "", "  ")
	if err != nil {
		return err
	}
	CertAuth, err := ca.New(op)
	if err != nil {
		return err
	}

	pemSubCert, err := CertAuth.PktToSignedX509(pktJson)
	if err != nil {
		return err
	}
	fmt.Println("Issued Cert: \n", string(pemSubCert))

	msg := []byte("All is discovered - flee at once")
	signedMsg, err := pkt.NewSignedMessage(msg, opkClient.GetSigner())
	if err != nil {
		return err
	}
	println("Signed Message: \n", string(signedMsg))

	err = CertAuth.VerifyPktCert(pemSubCert)
	if err != nil {
		return err
	}

	return nil
}
