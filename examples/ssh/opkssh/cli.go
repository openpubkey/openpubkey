package main

import (
	"crypto"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/examples/ssh/sshcert"
	"github.com/openpubkey/openpubkey/parties"
	"github.com/openpubkey/openpubkey/util"
)

// This function is called by the SSH server as the AuthorizedKeysCommand:
//
// The following lines are added to /etc/ssh/sshd_config:
//
//	AuthorizedKeysCommand /etc/opk/opkssh ver %u %t %k
//	AuthorizedPrincipalsCommandUser root
//
// The parameters specified in the config map the parameters send the function below. They are:
// %u The username (requested principal) - userArg
// %t The public key type - typArg - in this case a certification being used as a public key
// %k The base64-encoded public key for authentication - certB64Arg - the public key is also a certificate
func AuthorizedKeysCommand(userArg string, typArg string, certB64Arg string, policyEnforcer sshcert.PolicyCheck, op parties.OpenIdProvider) (string, error) {
	cert, err := sshcert.NewSshCertFromBytes(typArg, certB64Arg)
	if err != nil {
		return "", err
	}

	if err := sshcert.CheckCert(userArg, cert, policyEnforcer, op); err != nil {
		return "", err
	} else {
		// sshd expects the public key in the cert, not the cert itself.
		// This public key is key of the CA the signs the cert, in our
		// setting there is no CA.
		pubkeyBytes := ssh.MarshalAuthorizedKey(cert.Cert.SignatureKey)
		return "cert-authority " + string(pubkeyBytes), nil
	}
}

func RequestSSHCert(client *parties.OpkClient, signer crypto.Signer, alg jwa.KeyAlgorithm, gqFlag bool, principals []string) ([]byte, []byte, error) {
	pkt, err := client.OidcAuth(signer, alg, map[string]any{}, gqFlag)

	cert, err := sshcert.BuildSshCert(pkt, principals)
	if err != nil {
		return nil, nil, err
	}
	caSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return nil, nil, err
	}

	mas, err := ssh.NewSignerWithAlgorithms(caSigner.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoECDSA256})
	if err != nil {
		return nil, nil, err
	}

	sshcert, err := cert.SignCert(mas)

	if err != nil {
		return nil, nil, err
	}
	certBytes := ssh.MarshalAuthorizedKey(sshcert)

	seckeySsh, err := ssh.MarshalPrivateKey(signer, "openpubkey cert")
	if err != nil {
		return nil, nil, err
	}
	seckeySshBytes := pem.EncodeToMemory(seckeySsh)

	return certBytes, seckeySshBytes, nil
}

func log(line string) {
	f, err := os.OpenFile("/var/log/openpubkey.log", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0700)
	if err != nil {
		fmt.Println("Couldn't write to file")
	} else {
		defer f.Close()
		if _, err = f.WriteString(line + "\n"); err != nil {
			fmt.Println("Couldn't write to file")
		}
	}
}

// This code is currently intended as an example for how OpenPubkey can secure SSH access. It is still under active development.
func main() {
	if len(os.Args) < 2 {
		fmt.Printf("OpenPubkey SSH CLI: command choices are login, ver, config")
		return
	}
	command := os.Args[1]

	op := parties.GoogleOp{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Issuer:       issuer,
		Scopes:       scopes,
		RedirURIPort: redirURIPort,
		CallbackPath: callbackPath,
		RedirectURI:  redirectURI,
	}

	// TODO: Use a command parser so that users can specify filepaths for keys and supply their own certificates
	// TODO: Store keys in SSH Agent rather than the current directory in the filesystem
	// TODO: Access log should be optional, support windows and osx, and use a logger
	// TODO: Add command that will check security of server configuration,
	//   e.g., alarm if TrustedUserCAKeys is enabled in sshd_config without AuthorizedPrincipalsCommand, policy file is only root writable, ...
	// TODO: Support the github OP
	// TODO: Support certificate signing algorithms other than RSA
	switch command {
	case "config":
		{
			fmt.Printf("To configure an ssh server: \n" +
				"====:\n" +
				"1. Install opkssh verify on server: \n" +
				"   sudo mkdir /etc/opk/ \n" +
				"   sudo cp opkssh /etc/opk/ \n" +
				"   sudo chown root /etc/opk/opkssh \n" +
				"   sudo chmod 700 /etc/opk/opkssh \n" +
				"2. Configure the sshd_config by adding the following lines to /etc/ssh/sshd_config: \n" +
				"   TrustedUserCAKeys /etc/ssh/opk_user_ca.pub \n" +
				"   AuthorizedKeyCommand /etc/opk/opkssh ver %%u %%t %%k \n" +
				"   AuthorizedKeyCommandUser root \n" +
				"3. Restart sshd server: \n" +
				"   systemctl restart sshd \n" +
				"4. Create policy file: \n" +
				"   sudo vim /etc/opk/policy \n" +
				"   sudo chown root /etc/opk/policy \n" +
				"   sudo chmod 600 /etc/opk/policy \n")
		}
	case "login":
		{
			if len(os.Args) != 3 {
				fmt.Println("Invalid number of arguments for login, should be `opkssh login <identity>`")
				os.Exit(1)
			}

			principals := strings.Split(os.Args[2], ",")
			principals = []string{}

			// TODO: Use SSH Agent
			seckeyPath := "./ssh-key"
			pubkeyPath := seckeyPath + ".pub"
			gqFalse := false
			alg := jwa.ES256

			signer, err := util.GenKeyPair(alg)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			client := &parties.OpkClient{
				Op: &op,
			}

			certBytes, seckeySshPem, err := RequestSSHCert(client, signer, alg, gqFalse, principals)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			// Write ssh secret key to filesystem
			err = os.WriteFile(seckeyPath, seckeySshPem, 0600)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			// Write ssh public key (certificate) to filesystem
			err = os.WriteFile(pubkeyPath, certBytes, 0777)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			os.Exit(0)
		}
	case "ver":
		{
			log(strings.Join(os.Args, " "))

			policyEnforcer := sshcert.SimpleFilePolicyEnforcer{
				PolicyFilePath: "/etc/opk/policy",
			}

			userArg := os.Args[2]
			certB64Arg := os.Args[3]
			typArg := os.Args[4]

			authKey, err := AuthorizedKeysCommand(userArg, typArg, certB64Arg, policyEnforcer.CheckPolicy, &op)
			if err != nil {
				log(fmt.Sprint(err))
				os.Exit(1)
			} else {
				fmt.Println(authKey)
				os.Exit(0)
			}
		}
	default:
		fmt.Printf("Error! No valid command")
	}
}
