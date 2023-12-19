package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/bastionzero/opk-ssh/commands"
	"github.com/bastionzero/opk-ssh/internal"
	"github.com/bastionzero/opk-ssh/policy"
	"github.com/bastionzero/opk-ssh/sshcert"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/pktoken"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

var (
	avilableURIPorts = []int{49172, 51252, 58243, 59360, 62109}
)

// This code is currently intended as an example for how OpenPubkey can secure SSH access.
func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Example SSH key generator using OpenPubkey: command choices are: login, ver")
		return
	}
	command := os.Args[1]

	var redirectURIPort int
	var err error
	if redirectURIPort, err = retrieveOpenPort(); err != nil {
		fmt.Print(err)
		os.Exit(1)
	}

	// OIDC provider is hardcoded to Google for now
	op := internal.GoogleOp

	op.RedirURIPort = fmt.Sprint(redirectURIPort)
	op.RedirectURI = fmt.Sprintf("http://localhost:%s%s", op.RedirURIPort, op.CallbackPath)

	switch command {
	case "login":
		if len(os.Args) != 2 {
			fmt.Println("ERROR login does not accept any arguments")
			os.Exit(1)
		}

		// Execute login command
		err := commands.Login(&op)
		if err != nil {
			fmt.Printf("login error: %s", err)
			os.Exit(1)
		}

		os.Exit(0)
	case "verify":
		// Setup logger
		logPath := "/var/log/openpubkey.log"
		logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0700)
		if err != nil {
			fmt.Println("ERROR opening log file:", err)
			os.Exit(1)
		}
		defer logFile.Close()
		log.SetOutput(logFile)

		// The "verify" command is designed to be used by sshd and specified as an AuthorizedKeysCommand
		// ref: https://man.openbsd.org/sshd_config#AuthorizedKeysCommand
		{
			log.Println(strings.Join(os.Args, " "))

			// These arguments are sent by sshd and dictated by the pattern as defined in the sshd config
			// Example line in sshd config:
			// 		AuthorizedKeysCommand /etc/opk/opk-ssh verify %u %k %t
			//
			//	%u The desired user being assumed on the target (aka requested principal).
			//	%k The base64-encoded public key for authentication.
			//	%t The public key type, in this case an ssh certificate being used as a public key.
			if len(os.Args) != 5 {
				fmt.Println("Invalid number of arguments for verify, expected: `<User (TOKEN u)> <Key type (TOKEN t)> <Cert (TOKEN k)>`")
				os.Exit(1)
			}
			userArg := os.Args[2]
			certB64 := os.Args[3]
			pubkeyType := os.Args[4]

			usr, err := user.Lookup(userArg)
			if err != nil {
				fmt.Printf("failed to find home directory for the principal: %s\n", userArg)
				os.Exit(1)
			}

			// if user is non root, the filepath will be ~/policy.yml
			// otherwise, it will default to /etc/opk/policy.yml
			_, policyFilePath, err := policy.GetPolicy(userArg, usr.HomeDir)

			policyEnforcer := policy.Enforcer{
				PolicyFilePath: policyFilePath,
			}

			authKey, err := authorizedKeysCommand(userArg, certB64, pubkeyType, policyEnforcer.CheckPolicy, &op)
			if err != nil {
				log.Println(err)
				os.Exit(1)
			} else {
				fmt.Println(authKey)
				os.Exit(0)
			}
		}
	case "add":
		// The "add" command is designed to be used by the client configuration
		// script to inject user entries into the policy file
		{
			// Example line to add a user:
			// 		./opk-ssh add %e %p
			//
			//  %e The email of the user to be added to the policy file.
			//	%p The desired principal being assumed on the target (aka requested principal).
			if len(os.Args) != 4 {
				fmt.Println("Invalid number of arguments for verify, expected: `<Email (TOKEN e)> <Principal (TOKEN p)>`")
				os.Exit(1)
			}
			inputEmail := os.Args[2]
			inputPrincipal := os.Args[3]

			usr, err := user.Lookup(inputPrincipal)
			if err != nil {
				fmt.Printf("failed to find home directory for the principal: %s\n", inputPrincipal)
				os.Exit(1)
			}

			policyData, policyFilePath, err := policy.GetPolicy(inputPrincipal, usr.HomeDir)
			if err != nil {
				fmt.Printf("failed to get policy: %s\n", err)
				os.Exit(1)
			}

			users := policy.Users{}
			if err := yaml.Unmarshal([]byte(policyData), &users); err != nil {
				fmt.Printf("error unmarshalling policy file data: %s\n", err)
				os.Exit(1)
			}

			var userExists = false
			if len(users.Users) != 0 {
				// search to see if the current user already has an entry in the policy file
				for _, user := range users.Users {
					if user.Email == inputEmail {
						var principalExists = false
						for _, principal := range user.Principals {
							// if the principal already exists for this user, then skip
							if principal == inputPrincipal {
								fmt.Printf("User with email %s already has access under the principal %s, skipping...\n", inputEmail, inputPrincipal)
								principalExists = true
							}
						}

						if !principalExists {
							user.Principals = append(user.Principals, inputPrincipal)
							fmt.Printf("Successfully added user with email %s with principal %s to the policy file\n", inputEmail, inputPrincipal)
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
				fmt.Println("error writing to policy file:", err)
			} else {
				fmt.Println("Successfully added new policy to ", policyFilePath)
			}
		}
	default:
		fmt.Println("ERROR! Unrecognized command:", command)
	}
}

func authorizedKeysCommand(
	userArg string,
	certB64Arg string,
	pubkeyTypeArg string,
	policyCheck func(userDesired string, pkt *pktoken.PKToken) error,
	op client.OpenIdProvider,
) (string, error) {
	cert, err := sshcert.NewFromAuthorizedKey(pubkeyTypeArg, certB64Arg)
	if err != nil {
		return "", err
	}
	if pkt, err := cert.VerifySshPktCert(op); err != nil {
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

// Retrieve an open port
func retrieveOpenPort() (port int, err error) {
	for index, port := range avilableURIPorts {
		fmt.Printf(strconv.Itoa(index), port)
		available, err := checkPortIsAvailable(port)
		if err != nil {
			fmt.Printf("Port %d is not available.", port)
		} else if available {
			return port, nil
		}
	}

	return 0, fmt.Errorf("failed to retrieve open port: callback listener could not bind to any of the default ports")
}

// Reference -> https://gist.github.com/montanaflynn/b59c058ce2adc18f31d6
// Check if a port is available
func checkPortIsAvailable(port int) (status bool, err error) {

	// Concatenate a colon and the port
	host := fmt.Sprintf(":%d", port)

	// Try to create a server with the port
	server, err := net.Listen("tcp", host)

	// if it fails then the port is likely taken
	if err != nil {
		return false, err
	}

	// close the server
	server.Close()

	// we successfully used and closed the port
	// so it's now available to be used again
	return true, nil

}
