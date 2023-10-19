package main

import (
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/openpubkey/openpubkey/examples/ssh/sshcert"
	"github.com/openpubkey/openpubkey/parties"
	"github.com/openpubkey/openpubkey/pktoken"
)

func NewSshPublicSignerPublicKey() []byte {
	publicCAPubkey := []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDWHxxYH2JXSa1WoS0pUgwLmaxXx8lldNL6RInowpwp+wmAbXuKR8ADPQmMdr7TzEexFMqojGNSVACPdhTLIYCrk2PSgqvbHIhwDAPsK4iujoTfsGQR9DojR0F00m5kzD/Bt0VcgNdQi5nnf9iXKfcuIEmmJEKUlsAuzWB2UtUMocFXpyMqDHxsBGT9DDWggSFHYtUeSo3zzbmUN9ecu3GEwqLDS0xf9EKAmgD7Ko7y9goJ6XmIqiL3RaUqmCZyrp760K5Ir++pl1RRG/6EPVPDjiMvyDPdz1n1Amv5kmCsDrYnaMNy+tmWmZa9cP98KJ+Zvc2i4LklIuo7nMl13qzP openpubkey")
	return publicCAPubkey
}

// Our protocol relies on using the certificate to smuggle the PK Token into
// the SSH session so that it can be sent to AuthorizedPrincipalsCommand
// which then authenicates the PK Token and session. Thus, we do not rely
// on the certificate itself as an authentication mechanism but rather use it
// as a delivery mechanism. To enable this protocol to be used without
// requiring that a user deploy and manage a SSH Certificate Authority, we bake
// a public "signing key" into the CLI so that the CLI can issue certificates
// by itself. As the signing key for these certificates is public anyone can
// issue certificates that will verify under the associated public key. These
// certificates SHOULD NOT be used for authentication! Rather the PK Token in
// the extension field of the certification functions as the actual
// authentication mechanism.
//
// Note that users and organizations that are willing to deploy and manage an
// SSH certificate authority can use a signing key which is kept secret. In
// such settngs the certificate would function as an additional authentication
// mechanism.
func NewSshPublicSigner() (ssh.MultiAlgorithmSigner, error) {
	publicCASeckey := []byte(strings.ReplaceAll(
		`-----BEGIN PUBLIC VALUE: DO NOT TRUST TO ESTABLISH AUTHENTICATION-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA1h8cWB9iV0mtVqEtKVIMC5msV8fJZXTS+kSJ6MKcKfsJgG17ikfA
Az0JjHa+08xHsRTKqIxjUlQAj3YUyyGAq5Nj0oKr2xyIcAwD7CuIro6E37BkEfQ6I0dBdN
JuZMw/wbdFXIDXUIuZ53/Ylyn3LiBJpiRClJbALs1gdlLVDKHBV6cjKgx8bARk/Qw1oIEh
R2LVHkqN8825lDfXnLtxhMKiw0tMX/RCgJoA+yqO8vYKCel5iKoi90WlKpgmcq6e+tCuSK
/vqZdUURv+hD1Tw44jL8gz3c9Z9QJr+ZJgrA62J2jDcvrZlpmWvXD/fCifmb3NouC5JSLq
O5zJdd6szwAAA8CFSfwthUn8LQAAAAdzc2gtcnNhAAABAQDWHxxYH2JXSa1WoS0pUgwLma
xXx8lldNL6RInowpwp+wmAbXuKR8ADPQmMdr7TzEexFMqojGNSVACPdhTLIYCrk2PSgqvb
HIhwDAPsK4iujoTfsGQR9DojR0F00m5kzD/Bt0VcgNdQi5nnf9iXKfcuIEmmJEKUlsAuzW
B2UtUMocFXpyMqDHxsBGT9DDWggSFHYtUeSo3zzbmUN9ecu3GEwqLDS0xf9EKAmgD7Ko7y
9goJ6XmIqiL3RaUqmCZyrp760K5Ir++pl1RRG/6EPVPDjiMvyDPdz1n1Amv5kmCsDrYnaM
Ny+tmWmZa9cP98KJ+Zvc2i4LklIuo7nMl13qzPAAAAAwEAAQAAAQBP3p72CA7ovGTaEZkE
9sPjd9kfjTiEjcU88V/34M/boPZ0X2JbvFPVYWk0af7YhjSfyz+lC2jpBsiGuucatk6GsZ
3kojV0r/n8wZ6c88gyRJsvzV4mjFE7Y5L4/p2LH90QZ0qKLM0kEE7CWZ/zEwZOwGB4hsIH
Jwxc6OL4gAFUijp8omqBEGs/CpWKwrWZ9IqZxCHqd8ayGKPAHcTDjUcqItNxr4NEnw/GF3
tdGKkbuoPn9D7yFvH0uYsc2ReJhl1nKv4+oZLLyX4wpT/XnATX50m9mPR6Tw6wUUXlNl9M
LAJp7vhJ4v5FhCbRclLpNtVEpOVElbUu795Wqlz8SOWRAAAAgQDGjinNzr11njyViZq5k3
OlYQHbDgA8HY6blwYdpzx3spr6x9HHrCdIaTNmTztcqiisO1Bq6kHY9t4vlTLj/z1vblzn
Nnhu6F7K6f27erMTQNrs8JPdckryLo0LNgS0VumX7QJyoRz+yMnJg7K7kcUqIy/bKot4UN
wVGOU4CYqRagAAAIEA1oGdo98dMk7Z6wtK79y+SkXn0drKNanZuqNJhhKiLNJTbtxUHZkE
Vl7cN4OuipfglWM0qEcWkCcMQtxtgyWl4SogLkbx+IoVcRcmSLRgD2wXqqa3dG4k/44UeF
ZiEf+jhl8a7EqBDcok+ntp6ozJelOhUF0ScAfBcwzIrPJb1esAAACBAP+KcLgJKRePexAu
83jHEZrZ3hTvKZ/AZinz04WSXwaVN6nP8B1USR6IP+sjikcfH+56bclV9MuuHIZTO56aXG
HwL210SZBbYjMLAkriG6z6syuuocOcncwShmw1Kprs5FeeZr2eReUYBHjYenAxhBCmPjsz
DPPto1eoC7jABRetAAAAB3VzZXJfY2EBAgM=
-----END PUBLIC VALUE: DO NOT TRUST TO ESTABLISH AUTHENTICATION-----`,
		"PUBLIC VALUE: DO NOT TRUST TO ESTABLISH AUTHENTICATION", "OPENSSH PRIVATE KEY"))
	return sshcert.NewSshSignerFromPem(publicCASeckey)
}

// This function is called by the SSH server as the AuthorizedPrincipalsCommand:
//
// The following lines are added to /etc/ssh/sshd_config:
//
//	TrustedUserCAKeys <path to CA public key>
//	X AuthorizedPrincipalsCommand /etc/opk/opkssh ver %u %i %t %K %k %s %T
//	AuthorizedPrincipalsCommand /etc/opk/opkssh ver %u %t %k
//	AuthorizedPrincipalsCommandUser root
//
// The parameters specified in the config map the parameters send the function below. They are:
// %u The username (requested principal) - userArg
// %t The certificate type - typArg
// %k The base64-encoded certificate for authentication - certB64Arg
func AuthorizedPrincipalsCommand(userArg string, typArg string, certB64Arg string, policyEnforcer sshcert.PolicyEnforcer, op parties.OpenIdProvider) (string, error) {
	certB64 := typArg + " " + certB64Arg
	certPubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certB64))
	if err != nil {
		return "", err
	}
	cert := certPubkey.(*ssh.Certificate)

	if err := sshcert.CheckCert(userArg, cert, policyEnforcer, op); err != nil {
		return "", err
	} else {
		return userArg, nil
	}
}

func RequestSSHCert(client *parties.OpkClient, principals []string, certIssuer sshcert.CertIssuer) ([]byte, []byte, []byte, error) {
	pktJson, err := client.OidcAuth()
	if err != nil {
		return nil, nil, nil, err
	}

	// Get Openpubkey certificate issued for your PK Token
	cert, err := certIssuer(pktJson, principals)
	if err != nil {
		return nil, nil, nil, err
	}

	certBytes := ssh.MarshalAuthorizedKey(cert)

	pubkeySsh, err := ssh.NewPublicKey(&(client.Signer.Pksk.PublicKey))
	if err != nil {
		return nil, nil, nil, err
	}
	pubkeySshBytes := ssh.MarshalAuthorizedKey(pubkeySsh)

	seckeySsh, err := ssh.MarshalPrivateKey(client.Signer.Pksk, "openpubkey cert")
	if err != nil {
		return nil, nil, nil, err
	}
	seckeySshBytes := pem.EncodeToMemory(seckeySsh)

	return certBytes, pubkeySshBytes, seckeySshBytes, nil
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
			fmt.Printf("To configure an ssh server: \n"+
				"====:\n"+
				"1. Install opkssh verify on server: \n"+
				"   sudo mkdir /etc/opk/ \n"+
				"   sudo cp opkssh /etc/opk/ \n"+
				"   sudo chown root /etc/opk/opkssh \n"+
				"   sudo chmod 700 /etc/opk/opkssh \n"+
				"2. Install CA public key \n"+
				" sudo echo \"%s\" > /etc/ssh/opk_user_ca.pub \n"+
				"3. Configure the sshd_config by adding the following lines to /etc/ssh/sshd_config: \n"+
				"   TrustedUserCAKeys /etc/ssh/opk_user_ca.pub \n"+
				"   AuthorizedPrincipalsCommand /etc/opk/opkssh ver %%u %%t %%k \n"+
				"   AuthorizedPrincipalsCommandUser root \n"+
				"4. Restart sshd server: \n"+
				"   systemctl restart sshd \n"+
				"5. Create policy file: \n"+
				"   sudo vim /etc/opk/policy \n"+
				"   sudo chown root /etc/opk/policy \n"+
				"   sudo chmod 600 /etc/opk/policy \n",
				string(NewSshPublicSignerPublicKey()))
		}
	case "login":
		{
			if len(os.Args) != 3 {
				fmt.Println("Invalid number of arguments for login, should be `opkssh login <identity>`")
				os.Exit(1)
			}

			principals := strings.Split(os.Args[2], ",")

			// TODO: Use SSH Agent
			seckeyPath := "./ssh-key"
			pubkeyPath := seckeyPath + ".pub"
			certPath := "./ssh-key-cert.pub"
			opkClientAlg := "ES256"
			gqFalse := false

			signer, err := pktoken.NewSigner(fpClientCfg, opkClientAlg, gqFalse, map[string]any{})
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			client := &parties.OpkClient{
				Op:     &op,
				Signer: signer,
			}

			caSigner, err := NewSshPublicSigner()
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			ca := sshcert.SshCa{
				Signer: caSigner,
			}

			certBytes, pubkeySshBytes, seckeySshPem, err := RequestSSHCert(client, principals, ca.IssueCert)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			// Write issued cert to filesystem
			err = os.WriteFile(certPath, certBytes, 0644)
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

			// Write ssh public key to filesystem
			err = os.WriteFile(pubkeyPath, pubkeySshBytes, 0777)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			os.Exit(0)
		}
	case "ver":
		{
			f, err := os.OpenFile("/var/log/openpubkey.log", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0700)
			if err != nil {
				fmt.Println("Couldn't write to file")
			} else {
				defer f.Close()
				if _, err = f.WriteString(strings.Join(os.Args, " ") + "\n"); err != nil {
					fmt.Println("Couldn't write to file")
				}
			}
			userArg := os.Args[2]
			typArg := os.Args[3]
			certB64Arg := os.Args[4]

			principal, err := AuthorizedPrincipalsCommand(userArg, typArg, certB64Arg, sshcert.SimpleFilePolicyEnforcer, &op)
			if err != nil {
				os.Exit(1)
			} else {
				fmt.Println(principal)
				os.Exit(0)
			}
		}
	default:
		fmt.Printf("Error! No valid command")
	}
}
