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
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/openpubkey/openpubkey/client/choosers"
	"github.com/openpubkey/openpubkey/opkssh/commands"
	"github.com/openpubkey/openpubkey/opkssh/config"
	"github.com/openpubkey/openpubkey/opkssh/policy"
	"github.com/openpubkey/openpubkey/providers"
)

var (

	// These can be overridden at build time using ldflags. For example:
	// go build -v -o /etc/opk/opkssh -ldflags "-X main.issuer=http://oidc.local:${ISSUER_PORT}/ -X main.clientID=web -X main.clientSecret=secret"
	issuer       = ""
	clientID     = ""
	clientSecret = ""
	redirectURIs = ""
)

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 2 {
		fmt.Println("Example SSH key generator using OpenPubkey: command choices are: login, verify, and add")
		return 1
	}
	command := os.Args[1]

	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		cancel()
	}()

	var providerFromEnv providers.OpenIdProvider
	if issuer != "" {
		opts := providers.GetDefaultGoogleOpOptions() // TODO: Create default google like provider
		opts.Issuer = issuer
		opts.ClientID = clientID
		opts.ClientSecret = clientSecret
		opts.RedirectURIs = strings.Split(redirectURIs, ",")
		providerFromEnv = providers.NewGoogleOpWithOptions(opts)
	}

	switch command {
	case "login":
		loginCmd := flag.NewFlagSet("login", flag.ExitOnError)
		autoRefresh := loginCmd.Bool("auto-refresh", false, "Used to specify whether login will begin a process that auto-refreshes PK token")
		logFilePath := loginCmd.String("log-dir", "", "Specify which directory the output log is placed")
		if err := loginCmd.Parse(os.Args[2:]); err != nil {
			log.Println("ERROR parsing args:", err)
			return 1
		}

		// If a log directory was provided, write any logs to a file in that directory AND stdout
		if *logFilePath != "" {
			logFilePath := filepath.Join(*logFilePath, "openpubkey.log")
			logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0700)
			if err == nil {
				defer logFile.Close()
				multiWriter := io.MultiWriter(os.Stdout, logFile)
				log.SetOutput(multiWriter)
			}
		}

		var provider providers.OpenIdProvider
		if providerFromEnv != nil {
			provider = providerFromEnv
		} else {
			googleOpOptions := providers.GetDefaultGoogleOpOptions()
			googleOpOptions.GQSign = false
			googleOp := providers.NewGoogleOpWithOptions(googleOpOptions)

			azureOpOptions := providers.GetDefaultAzureOpOptions()
			azureOpOptions.GQSign = false
			azureOp := providers.NewAzureOpWithOptions(azureOpOptions)

			var err error
			provider, err = choosers.NewWebChooser(
				[]providers.BrowserOpenIdProvider{googleOp, azureOp},
			).ChooseOp(context.Background())
			if err != nil {
				log.Println("ERROR selecting op:", err)
				return 1
			}
		}

		// Execute login command
		if *autoRefresh {
			if providerRefreshable, ok := provider.(providers.RefreshableOpenIdProvider); ok {
				err := commands.LoginWithRefresh(ctx, providerRefreshable)
				if err != nil {
					log.Println("ERROR logging in:", err)
				}
			} else {
				errString := fmt.Sprintf("ERROR OpenID Provider (%v) does not support auto-refresh and auto-refresh argument set to true", provider.Issuer())
				log.Println(errString)
				return 1
			}
		} else {
			err := commands.Login(ctx, provider)
			if err != nil {
				log.Println("ERROR logging in:", err)
				return 1
			}
		}

	case "verify":
		// Setup logger
		logFile, err := os.OpenFile("/var/log/openpubkey.log", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0700)
		if err != nil {
			fmt.Println("ERROR opening log file:", err)
		} else {
			defer logFile.Close()
			log.SetOutput(logFile)
		}

		// Logs if using an unsupported OpenSSH version
		checkOpenSSHVersion()

		// The "AuthorizedKeysCommand" func is designed to be used by sshd and specified as an AuthorizedKeysCommand
		// ref: https://man.openbsd.org/sshd_config#AuthorizedKeysCommand
		log.Println(strings.Join(os.Args, " "))

		// These arguments are sent by sshd and dictated by the pattern as defined in the sshd config
		// Example line in sshd config:
		// 		AuthorizedKeysCommand /etc/opk/opkssh verify %u %k %t
		//
		//	%u The desired user being assumed on the target (aka requested principal).
		//	%k The base64-encoded public key for authentication.
		//	%t The public key type, in this case an ssh certificate being used as a public key.
		if len(os.Args) != 5 {
			log.Println("Invalid number of arguments for verify, expected: `<User (TOKEN u)> <Key type (TOKEN t)> <Cert (TOKEN k)>`")
			return 1
		}
		userArg := os.Args[2]
		certB64Arg := os.Args[3]
		typArg := os.Args[4]

		providerPolicyPath := "/etc/opk/providers"
		providerPolicy, err := policy.NewProviderFileLoader().LoadProviderPolicy(providerPolicyPath)

		if err != nil {
			log.Println("Failed to open /etc/opk/providers:", err)
			return 1
		}
		printConfigProblems()
		log.Println("Providers loaded: ", providerPolicy.ToString())

		pktVerifier, err := providerPolicy.CreateVerifier()
		if err != nil {
			log.Println("Failed to create pk token verifier (likely bad configuration):", err)
			return 1
		}

		log.Println("Debugging in prod =(: ")

		// Execute verify command
		v := commands.VerifyCmd{
			PktVerifier: *pktVerifier,
			CheckPolicy: commands.OpkPolicyEnforcerFunc(userArg),
		}
		if authKey, err := v.AuthorizedKeysCommand(ctx, userArg, typArg, certB64Arg); err != nil {
			log.Println("failed to verify:", err)
			return 1
		} else {
			log.Println("successfully verified")
			// sshd is awaiting a specific line, which we print here. Printing anything else before or after will break our solution
			fmt.Println(authKey)
			return 1
		}
	case "add":
		// The "add" command is designed to be used by the client configuration
		// script to inject user entries into the policy file
		//
		// Example line to add a user:
		// 		./opkssh add %p %e %i
		//	%p The desired principal being assumed on the target (aka requested principal).
		//  %e The email of the user to be added to the policy file.
		//	%i The desired OpenID Provider for email, e.g. https://accounts.google.com.
		if len(os.Args) != 5 {
			fmt.Println("Invalid number of arguments for add, expected: `<Email (TOKEN e)> <Issuer (TOKEN i) <Principal (TOKEN p)>`")
			return 1
		}
		inputPrincipal := os.Args[2]
		inputEmail := os.Args[3]
		inputIssuer := os.Args[4]

		// Convenience aliases to save user time (who is going to remember the hideous Azure issuer string)
		switch inputIssuer {
		case "google":
			inputIssuer = "https://accounts.google.com"
		case "azure", "microsoft":
			inputIssuer = "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"
		}

		// Execute add command
		a := commands.AddCmd{
			PolicyFileLoader: policy.NewUserFileLoader(),
			Username:         inputPrincipal,
		}
		if policyFilePath, err := a.Add(inputPrincipal, inputEmail, inputIssuer); err != nil {
			log.Println("failed to add to policy:", err)
			return 1
		} else {
			log.Println("Successfully added new policy to", policyFilePath)
		}
	default:
		log.Println("ERROR! Unrecognized command:", command)
		return 1
	}

	return 0
}

func printConfigProblems() {
	problems := config.ConfigProblems().GetProblems()
	if len(problems) > 0 {
		log.Println("Warning: Encountered the following configuration problems:")
		for _, problem := range problems {
			log.Println(problem.String())
		}
	}
}

// OpenSSH used to impose a 4096-octet limit on the string buffers available to
// the percent_expand function. In October 2019 as part of the 8.1 release,
// that limit was removed. If you exceeded this amount it would fail with
// fatal: percent_expand: string too long
// The following two functions check whether the OpenSSH version on the
// system running the verifier is greater than or equal to 8.1;
// if not then prints a warning
func checkOpenSSHVersion() {
	cmd := exec.Command("sshd", "-V")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Error executing ssh -V:", err)
		return
	}

	if ok, _ := isOpenSSHVersion8Dot1OrGreater(string(output)); !ok {
		log.Println("OpenPubkey SSH requires OpenSSH v. 8.1 or greater")
	}
}

func isOpenSSHVersion8Dot1OrGreater(opensshVersion string) (bool, error) {
	// To handle versions like 9.9p1; we only need the initial numeric part for the comparison
	re, err := regexp.Compile(`^(\d+(?:\.\d+)*).*`)
	if err != nil {
		fmt.Println("Error compiling regex:", err)
		return false, err
	}

	opensshVersion = strings.TrimPrefix(
		strings.Split(opensshVersion, ", ")[0],
		"OpenSSH_",
	)

	matches := re.FindStringSubmatch(opensshVersion)

	if matches == nil || len(matches) <= 0 {
		fmt.Println("Invalid OpenSSH version")
		return false, errors.New("invalid OpenSSH version")
	}

	version := matches[1]

	if version >= "8.1" {
		return true, nil
	}

	return false, nil
}
