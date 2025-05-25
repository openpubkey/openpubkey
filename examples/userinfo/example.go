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
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/awnumar/memguard"

	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/client/choosers"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/verifier"
)

func main() {
	// Safely terminate in case of an interrupt signal
	memguard.CatchInterrupt()

	// Purge the session when we return
	defer memguard.Purge()

	if len(os.Args) < 2 {
		fmt.Printf("OpenPubkey: command choices are login")
		return
	}

	command := os.Args[1]
	switch command {
	case "login":
		if err := login(); err != nil {
			fmt.Println("Error logging in:", err)
		} else {
			fmt.Println("Login successful!")
		}
	default:
		fmt.Println("Unrecognized command:", command)
	}
}

func login() error {
	googleOpOptions := providers.GetDefaultGoogleOpOptions()
	googleOp := providers.NewGoogleOpWithOptions(googleOpOptions)

	azureOpOptions := providers.GetDefaultAzureOpOptions()
	azureOp := providers.NewAzureOpWithOptions(azureOpOptions)

	gitlabOpOptions := providers.GetDefaultGitlabOpOptions()
	gitlabOp := providers.NewGitlabOpWithOptions(gitlabOpOptions)

	helloOpOptions := providers.GetDefaultHelloOpOptions()
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
		[]providers.BrowserOpenIdProvider{googleOp, azureOp, helloOp, gitlabOp},
		openBrowser,
	).ChooseOp(ctx)
	if err != nil {
		return err
	}

	opkClient, err := client.New(op)
	if err != nil {
		return err
	}

	pkt, err := opkClient.Auth(ctx)
	if err != nil {
		return err
	}

	accessToken := opkClient.GetAccessToken()
	fmt.Println("AccessToken", string(accessToken))

	uiRequester, err := verifier.NewUserInfoRequester(pkt, string(accessToken))
	if err != nil {
		return err
	}

	userInfoJson, err := uiRequester.Request(ctx)

	if err != nil {
		return err
	}
	fmt.Println("UserInfo", string(userInfoJson))

	return nil
}
