package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path"
	"strings"
	"syscall"

	"github.com/bastionzero/opk-ssh/commands"
	"github.com/bastionzero/opk-ssh/policy"
	"github.com/bastionzero/opk-ssh/provider"
	"github.com/bastionzero/opk-ssh/sshcert"
	"github.com/openpubkey/openpubkey/pktoken"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

var (
	issuer           = "https://accounts.google.com"
	clientID         = "878305696756-dd5ns57fccufrruii19fd7ed6jpd155r.apps.googleusercontent.com"
	clientSecret     = "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"
	redirectEndpoint = "/login-callback"
	redirectURIPorts = []int{49172, 51252, 58243, 59360, 62109}
)

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 2 {
		fmt.Printf("Example SSH key generator using OpenPubkey: command choices are: login, verify, and add")
		return 1
	}
	command := os.Args[1]

	provider, err := provider.NewGoogleProvider(issuer, clientID, clientSecret, redirectURIPorts, redirectEndpoint, nil, true, nil)
	if err != nil {
		log.Println("failed to create new google provider instance:", err)
		return 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		cancel()
	}()

	switch command {
	case "login":
		loginCmd := flag.NewFlagSet("login", flag.ExitOnError)
		autoRefresh := loginCmd.Bool("auto-refresh", false, "Used to specify whether login will begin a process that auto-refreshes PK token")
		logFilePath := loginCmd.String("log-dir", "", "Specify which directory the output log is placed")
		loginCmd.Parse(os.Args[2:])

		// If a log directory was provided, write any logs to a file in that directory AND stdout
		if *logFilePath != "" {
			logFilePath := path.Join(*logFilePath, "openpubkey.log")
			logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0700)
			if err == nil {
				defer logFile.Close()
				multiWriter := io.MultiWriter(os.Stdout, logFile)
				log.SetOutput(multiWriter)
			}
		}

		// Execute login command
		if *autoRefresh {
			err = commands.LoginWithRefresh(ctx, provider)
		} else {
			err = commands.Login(ctx, provider)
		}

		if err != nil {
			log.Println("ERROR logging in:", err)
			return 1
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

		// The "verify" command is designed to be used by sshd and specified as an AuthorizedKeysCommand
		// ref: https://man.openbsd.org/sshd_config#AuthorizedKeysCommand
		log.Println(strings.Join(os.Args, " "))

		// These arguments are sent by sshd and dictated by the pattern as defined in the sshd config
		// Example line in sshd config:
		// 		AuthorizedKeysCommand /etc/opk/opk-ssh verify %u %k %t
		//
		//	%u The desired user being assumed on the target (aka requested principal).
		//	%k The base64-encoded public key for authentication.
		//	%t The public key type, in this case an ssh certificate being used as a public key.
		if len(os.Args) != 5 {
			log.Println("Invalid number of arguments for verify, expected: `<User (TOKEN u)> <Key type (TOKEN t)> <Cert (TOKEN k)>`")
			return 1
		}
		userArg := os.Args[2]
		certB64 := os.Args[3]
		pubkeyType := os.Args[4]

		usr, err := user.Lookup(userArg)
		if err != nil {
			log.Printf("failed to find home directory for the principal %s: %v", userArg, err)
			return 1
		}

		// if user is non root, the filepath will be ~/policy.yml otherwise, it
		// will default to /etc/opk/policy.yml
		_, policyFilePath, err := policy.GetPolicy(userArg, usr.HomeDir)
		if err != nil {
			log.Printf("failed to get policy: %v", err)
			return 1
		}

		policyEnforcer := policy.Enforcer{
			PolicyFilePath: policyFilePath,
		}

		authKey, err := authorizedKeysCommand(ctx, userArg, certB64, pubkeyType, policyEnforcer.CheckPolicy, provider)
		if err != nil {
			log.Println(err)
			return 1
		} else {
			// sshd is awaiting a specific line, which we print here. Printing anything else before or after will break our solution
			fmt.Println(authKey)
		}
	case "add":
		// The "add" command is designed to be used by the client configuration
		// script to inject user entries into the policy file
		//
		// Example line to add a user:
		// 		./opk-ssh add %e %p
		//
		//  %e The email of the user to be added to the policy file.
		//	%p The desired principal being assumed on the target (aka requested principal).
		if len(os.Args) != 4 {
			fmt.Println("Invalid number of arguments for verify, expected: `<Email (TOKEN e)> <Principal (TOKEN p)>`")
			return 1
		}
		inputEmail := os.Args[2]
		inputPrincipal := os.Args[3]

		usr, err := user.Lookup(inputPrincipal)
		if err != nil {
			log.Println("failed to find home directory for the principal:", inputPrincipal)
			return 1
		}

		policyData, policyFilePath, err := policy.GetPolicy(inputPrincipal, usr.HomeDir)
		if err != nil {
			log.Println("failed to get policy:", err)
			return 1
		}

		users := policy.Users{}
		if err := yaml.Unmarshal([]byte(policyData), &users); err != nil {
			log.Println("error unmarshalling policy file data:", err)
			return 1
		}

		userExists := false
		if len(users.Users) != 0 {
			// search to see if the current user already has an entry in the policy file
			for _, user := range users.Users {
				if user.Email == inputEmail {
					principalExists := false
					for _, principal := range user.Principals {
						// if the principal already exists for this user, then skip
						if principal == inputPrincipal {
							log.Printf("User with email %s already has access under the principal %s, skipping...\n", inputEmail, inputPrincipal)
							principalExists = true
						}
					}

					if !principalExists {
						user.Principals = append(user.Principals, inputPrincipal)
						log.Printf("Successfully added user with email %s with principal %s to the policy file\n", inputEmail, inputPrincipal)
					}
					userExists = true
				}
			}
		}

		if len(users.Users) == 0 || !userExists {
			// if the policy file is empty, then create a new entry
			newUser := policy.User{
				Email:      inputEmail,
				Principals: []string{inputPrincipal},
			}
			// add the new user to the list of users in the policy
			users.Users = append(users.Users, newUser)
		}

		marshaledData, _ := yaml.Marshal(&users)
		if err := os.WriteFile(policyFilePath, marshaledData, 0); err != nil {
			log.Println("error writing to policy file:", err)
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

func authorizedKeysCommand(
	ctx context.Context,
	userArg string,
	certB64Arg string,
	pubkeyTypeArg string,
	policyCheck func(userDesired string, pkt *pktoken.PKToken) error,
	op *provider.GoogleProvider,
) (string, error) {
	cert, err := sshcert.NewFromAuthorizedKey(pubkeyTypeArg, certB64Arg)
	if err != nil {
		return "", err
	}
	if pkt, err := cert.VerifySshPktCert(ctx, op); err != nil {
		return "", err
	} else if err := policyCheck(userArg, pkt); err != nil {
		return "", err
	} else {
		// sshd expects the public key in the cert, not the cert itself.
		// This public key is key of the CA the signs the cert, in our
		// setting there is no CA.
		pubkeyBytes := ssh.MarshalAuthorizedKey(cert.SshCert.SignatureKey)
		return "cert-authority " + string(pubkeyBytes), nil
	}
}
