package main

import (
	"crypto"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"

	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/exp/slices"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/examples/ssh/sshcert"
	"github.com/openpubkey/openpubkey/parties"
	"github.com/openpubkey/openpubkey/pktoken"
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
// %t The public key type - typArg - in this case a certificate being used as a public key
// %k The base64-encoded public key for authentication - certB64Arg - the public key is also a certificate
func AuthorizedKeysCommand(userArg string, typArg string, certB64Arg string, policyEnforcer PolicyCheck, op parties.OpenIdProvider) (string, error) {
	cert, err := sshcert.NewSshCertFromBytes(typArg, certB64Arg)
	if err != nil {
		return "", err
	}
	if err := CheckCert(userArg, cert, policyEnforcer, op); err != nil {
		return "", err
	} else {
		// sshd expects the public key in the cert, not the cert itself.
		// This public key is key of the CA the signs the cert, in our
		// setting there is no CA.
		pubkeyBytes := ssh.MarshalAuthorizedKey(cert.SshCert.SignatureKey)
		return "cert-authority " + string(pubkeyBytes), nil
	}
}

func CheckCert(userDesired string, cert *sshcert.PktSshCert, policyEnforcer PolicyCheck, op parties.OpenIdProvider) error {
	pkt, err := cert.VerifySshPktCert(op)
	if err != nil {
		return err
	}
	err = policyEnforcer(userDesired, pkt)
	if err != nil {
		return err
	}
	return nil
}

type PolicyCheck func(userDesired string, pkt *pktoken.PKToken) error

type SimpleFilePolicyEnforcer struct {
	PolicyFilePath string
}

func (p *SimpleFilePolicyEnforcer) ReadPolicyFile() (string, []string, error) {
	info, err := os.Stat(p.PolicyFilePath)
	if err != nil {
		return "", nil, err
	}
	mode := info.Mode()

	// Only the owner of this file should be able to write to it
	if mode.Perm() != fs.FileMode(0600) {
		return "", nil, fmt.Errorf("policy file has insecure permissions, expected (0600), got (%o)", mode.Perm())
	}

	content, err := os.ReadFile(p.PolicyFilePath)
	if err != nil {
		return "", nil, err
	}
	rows := strings.Split(string(content), "\n")

	for i := range rows {
		row := strings.Fields(rows[i])
		if len(row) > 1 {
			email := row[0]
			allowedPrincipals := row[1:]
			return email, allowedPrincipals, nil
		}
	}
	return "", nil, fmt.Errorf("policy file contained no policy")
}

func (p *SimpleFilePolicyEnforcer) CheckPolicy(principalDesired string, pkt *pktoken.PKToken) error {
	allowedEmail, allowedPrincipals, err := p.ReadPolicyFile()
	if err != nil {
		return err
	}
	email, err := pkt.GetClaim("email")
	if err != nil {
		return err
	}
	if string(email) == allowedEmail {
		if slices.Contains(allowedPrincipals, principalDesired) {
			// Access granted
			return nil
		} else {
			return fmt.Errorf("no policy to allow %s to assume %s, check policy config in %s", email, principalDesired, p.PolicyFilePath)
		}
	} else {
		return fmt.Errorf("no policy for email %s, allowed email is %s, check policy config in %s", email, allowedEmail, p.PolicyFilePath)
	}
}

func CreateSSHCert(client *parties.OpkClient, signer crypto.Signer, alg jwa.KeyAlgorithm, gqFlag bool, principals []string) ([]byte, []byte, error) {
	pkt, err := client.OidcAuth(signer, alg, map[string]any{}, gqFlag)
	cert, err := sshcert.BuildPktSshCert(pkt, principals)
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

func WriteKeys(seckeyPath string, pubkeyPath string, seckeySshPem []byte, certBytes []byte) error {
	// Write ssh secret key to filesystem
	err := os.WriteFile(seckeyPath, seckeySshPem, 0600)
	if err != nil {
		return err
	}
	certBytes = append(certBytes, []byte(" "+"openpubkey")...)

	// Write ssh public key (certificate) to filesystem
	err = os.WriteFile(pubkeyPath, certBytes, 0777)
	if err != nil {
		return err
	}
	return nil
}

func FileExists(fPath string) bool {
	_, error := os.Open(fPath)
	return !errors.Is(error, os.ErrNotExist)
}

func WriteKeysToSSHDir(seckeySshPem []byte, certBytes []byte) error {
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
	defaultKeyNames := []string{"id_ecdsa_sk", "id_ecdsa", "id_dsa"}
	for i := range []string{"id_ecdsa_sk", "id_ecdsa", "id_dsa"} {
		seckeyPath := filepath.Join(sshPath, defaultKeyNames[i])
		pubkeyPath := seckeyPath + ".pub"

		if !FileExists(seckeyPath) {
			// If ssh key file does not currently exist, we don't have to worry about overwriting it
			return WriteKeys(seckeyPath, pubkeyPath, seckeySshPem, certBytes)
		} else if !FileExists(pubkeyPath) {
			continue
		} else {
			// If ssh key does file does exist, check if it is an openpubkey file, if it is then it is safe to overwrite
			sshPubkey, err := os.ReadFile(pubkeyPath)
			if err != nil {
				fmt.Println("Failed to read:", pubkeyPath)
				continue
			}
			sshPubkeyTok := strings.Split(string(sshPubkey), " ")
			if len(sshPubkeyTok) != 3 {
				fmt.Println("Failed to parse:", pubkeyPath)
				continue
			}
			// check if pubkey comment to see if it an openpubkey ssh key
			if strings.Contains(sshPubkeyTok[2], ("openpubkey")) {
				// safe to overwrite
				return WriteKeys(seckeyPath, pubkeyPath, seckeySshPem, certBytes)
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

// This code is currently intended as an example for how OpenPubkey can secure SSH access.
func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Example SSH key generator using OpenPubkey: command choices are: login, ver")
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

			client := &parties.OpkClient{
				Op: &op,
			}

			certBytes, seckeySshPem, err := CreateSSHCert(client, signer, alg, gqFalse, principals)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			// Write ssh secret key and public key to filesystem
			err = WriteKeysToSSHDir(seckeySshPem, certBytes)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			os.Exit(0)
		}
	case "ver":
		{
			log(strings.Join(os.Args, " "))
			policyEnforcer := SimpleFilePolicyEnforcer{
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
