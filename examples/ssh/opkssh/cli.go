package main

import (
	"context"
	"crypto"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"os"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/client/providers"
	"github.com/openpubkey/openpubkey/examples/ssh/sshcert"
	"github.com/openpubkey/openpubkey/util"
	"golang.org/x/crypto/ssh"
)

var (
	key              = []byte("NotASecureKey123")
	clientID         = "184968138938-g1fddl5tglo7mnlbdak8hbsqhhf79f32.apps.googleusercontent.com"
	requiredAudience = "184968138938-g1fddl5tglo7mnlbdak8hbsqhhf79f32.apps.googleusercontent.com"
	// The clientSecret was intentionally checked in for the purposes of this example,. It holds no power. Do not report as a security issue
	clientSecret = "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" // Google requires a ClientSecret even if this a public OIDC App
	scopes       = []string{"openid profile email"}
	redirURIPort = "3000"
	callbackPath = "/login-callback"
	redirectURI  = fmt.Sprintf("http://localhost:%v%v", redirURIPort, callbackPath)
)

// This code is currently intended as an example for how OpenPubkey can secure SSH access.
func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Example SSH key generator using OpenPubkey: command choices are: login, ver")
		return
	}
	command := os.Args[1]

	op := providers.GoogleOp{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		RedirURIPort: redirURIPort,
		CallbackPath: callbackPath,
		RedirectURI:  redirectURI,
	}

	switch command {
	case "login":
		{
			if len(os.Args) != 2 {
				fmt.Println("Invalid number of arguments for login, should be `opkssh login`")
				os.Exit(1)
			}

			// If principals is empty the server does not enforce any principal.
			// The OPK verifier should use policy to make this decision.
			principals := []string{}

			gqFalse := false
			alg := jwa.ES256

			signer, err := util.GenKeyPair(alg)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			client := &client.OpkClient{
				Op: &op,
			}

			certBytes, seckeySshPem, err := createSSHCert(context.Background(), client, signer, alg, gqFalse, principals)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			// Write ssh secret key and public key to filesystem
			err = writeKeysToSSHDir(seckeySshPem, certBytes)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			os.Exit(0)
		}
	case "ver":
		{
			log(strings.Join(os.Args, " "))
			policyEnforcer := simpleFilePolicyEnforcer{
				PolicyFilePath: "/etc/opk/policy",
			}

			if len(os.Args) != 5 {
				fmt.Println("Invalid number of arguments for ver, should be `opkssh ver <User (TOKEN u)> <Key type (TOKEN t)> <Cert (TOKEN k)> `")
				os.Exit(1)
			}
			userArg := os.Args[2]
			certB64Arg := os.Args[3]
			typArg := os.Args[4]

			authKey, err := authorizedKeysCommand(userArg, typArg, certB64Arg, policyEnforcer.checkPolicy, &op)
			if err != nil {
				log(fmt.Sprint(err))
				os.Exit(1)
			} else {
				fmt.Println(authKey)
				os.Exit(0)
			}
		}
	default:
		fmt.Println("Error! Unrecognized command:", command)
	}
}

// This function is called by the SSH server as the authorizedKeysCommand:
//
// The following lines are added to /etc/ssh/sshd_config:
//
//	authorizedKeysCommand /etc/opk/opkssh ver %u %t %k
//	AuthorizedPrincipalsCommandUser root
//
// The parameters specified in the config map the parameters sent to the function below.
// We prepend "Arg" to specify which ones are arguments sent by sshd. They are:
//
//	%u The username (requested principal) - userArg
//	%t The public key type - typArg - in this case a certificate being used as a public key
//	%k The base64-encoded public key for authentication - certB64Arg - the public key is also a certificate
func authorizedKeysCommand(userArg string, typArg string, certB64Arg string, policyEnforcer policyCheck, op client.OpenIdProvider) (string, error) {
	cert, err := sshcert.NewFromAuthorizedKey(typArg, certB64Arg)
	if err != nil {
		return "", err
	}
	if pkt, err := cert.VerifySshPktCert(op); err != nil {
		return "", err
	} else if err := policyEnforcer(userArg, pkt); err != nil {
		return "", err
	} else {
		// sshd expects the public key in the cert, not the cert itself.
		// This public key is key of the CA the signs the cert, in our
		// setting there is no CA.
		pubkeyBytes := ssh.MarshalAuthorizedKey(cert.SshCert.SignatureKey)
		return "cert-authority " + string(pubkeyBytes), nil
	}
}

func createSSHCert(cxt context.Context, client *client.OpkClient, signer crypto.Signer, alg jwa.KeyAlgorithm, gqFlag bool, principals []string) ([]byte, []byte, error) {
	pkt, err := client.OidcAuth(cxt, signer, alg, map[string]any{}, gqFlag)
	cert, err := sshcert.New(pkt, principals)
	if err != nil {
		return nil, nil, err
	}
	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return nil, nil, err
	}

	signerMas, err := ssh.NewSignerWithAlgorithms(sshSigner.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoECDSA256})
	if err != nil {
		return nil, nil, err
	}

	sshCert, err := cert.SignCert(signerMas)
	if err != nil {
		return nil, nil, err
	}
	certBytes := ssh.MarshalAuthorizedKey(sshCert)

	seckeySsh, err := ssh.MarshalPrivateKey(signer, "openpubkey cert")
	if err != nil {
		return nil, nil, err
	}
	seckeySshBytes := pem.EncodeToMemory(seckeySsh)

	return certBytes, seckeySshBytes, nil
}

func writeKeys(seckeyPath string, pubkeyPath string, seckeySshPem []byte, certBytes []byte) error {
	// Write ssh secret key to filesystem
	if err := os.WriteFile(seckeyPath, seckeySshPem, 0600); err != nil {
		return err
	}

	certBytes = append(certBytes, []byte(" "+"openpubkey")...)
	// Write ssh public key (certificate) to filesystem
	return os.WriteFile(pubkeyPath, certBytes, 0777)
}

func fileExists(fPath string) bool {
	_, err := os.Open(fPath)
	return !errors.Is(err, os.ErrNotExist)
}

func writeKeysToSSHDir(seckeySshPem []byte, certBytes []byte) error {
	homePath, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	sshPath := filepath.Join(homePath, ".ssh")

	//  To enable ssh to automatically find the key created by openpubkey we
	// need to use a default ssh key path. However this means that this
	// filename might already be in use by the user. To ensure we don't
	// overwrite a ssh key not created by openpubkey we check the comment in the
	// key to see if it was created by openpubkey
	for _, keyFilename := range []string{"id_ecdsa", "id_dsa"} {
		seckeyPath := filepath.Join(sshPath, keyFilename)
		pubkeyPath := seckeyPath + ".pub"

		if !fileExists(seckeyPath) {
			// If ssh key file does not currently exist, we don't have to worry about overwriting it
			return writeKeys(seckeyPath, pubkeyPath, seckeySshPem, certBytes)
		} else if !fileExists(pubkeyPath) {
			continue
		} else {
			// If ssh key does file does exist, check if it is an openpubkey file, if it is then it is safe to overwrite
			sshPubkey, err := os.ReadFile(pubkeyPath)
			if err != nil {
				fmt.Println("Failed to read:", pubkeyPath)
				continue
			}
			sshPubkeySplit := strings.Split(string(sshPubkey), " ")
			if len(sshPubkeySplit) != 3 {
				fmt.Println("Failed to parse:", pubkeyPath)
				continue
			}
			// check if pubkey comment to see if it an openpubkey ssh key
			if strings.Contains(sshPubkeySplit[2], ("openpubkey")) {
				// safe to overwrite
				return writeKeys(seckeyPath, pubkeyPath, seckeySshPem, certBytes)
			}
		}
	}
	return fmt.Errorf("no default ssh key file free for openpubkey")
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
