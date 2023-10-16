package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/zitadel/oidc/v2/pkg/oidc"

	"github.com/openpubkey/openpubkey/parties"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
)

// TODO: Create nice golang services rather than just using this handler nonsense

type ReceiveIDTHandler func(tokens *oidc.Tokens[*oidc.IDTokenClaims])

func login() error {
	signer, err := pktoken.NewSigner(fpClientCfg, keyAlgorithm.String(), gq, map[string]any{"extra": "yes"})
	if err != nil {
		return err
	}

	client := &parties.OpkClient{
		Op: &parties.GoogleOp{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Issuer:       issuer,
			Scopes:       scopes,
			RedirURIPort: redirURIPort,
			CallbackPath: callbackPath,
			RedirectURI:  redirectURI,
		},
		Signer: signer,
	}

	pktJson, err := client.OidcAuth()
	if err != nil {
		return err
	}

	// Pretty print our json token
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, pktJson, "", "  "); err != nil {
		return err
	}

	fmt.Println(prettyJSON.String())

	// Save our signer and pktoken by writing them to a file
	return signer.WriteToFile()
}

func googleSign(message string) error {
	signer, err := pktoken.LoadFromFile(fpClientCfg, keyAlgorithm.String(), false, nil)
	if err != nil {
		return fmt.Errorf("failed to load client state: %w", err)
	}

	msgHash := sha256.New()
	_, err = msgHash.Write([]byte(message))
	if err != nil {
		return err
	}
	msgHashSum := msgHash.Sum(nil)

	rawSigma, err := signer.Pksk.Sign(rand.Reader, msgHashSum, crypto.SHA256)
	if err != nil {
		return err
	}

	fmt.Println("Praise Sigma: ", base64.StdEncoding.EncodeToString(rawSigma))
	fmt.Println("Hash: ", hex.EncodeToString(msgHashSum))
	fmt.Println("Cert: ")

	// Pretty print our json token
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, signer.PktJson, "", "  "); err != nil {
		return err
	}

	fmt.Println(prettyJSON.String())

	return nil
}

func googleCert() error {
	signer, err := pktoken.LoadFromFile(fpClientCfg, keyAlgorithm.String(), false, nil)
	if err != nil {
		return fmt.Errorf("failed to load client state: %w", err)
	}

	client := &parties.OpkClient{
		Op: &parties.GoogleOp{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Issuer:       issuer,
			Scopes:       scopes,
			RedirURIPort: redirURIPort,
			CallbackPath: callbackPath,
			RedirectURI:  redirectURI,
		},
		Signer: signer,
	}

	certBytes, err := client.RequestCert()
	if err != nil {
		return fmt.Errorf("failed to request certificate: %w", err)
	}
	fmt.Println("Cert received: ", string(certBytes))

	block, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse cert: %s", err)
	}

	skid := cert.SubjectKeyId

	fmt.Println("Cert skid: ", string(skid))

	skidDecoded, err := util.Base64DecodeForJWT(skid)
	if err != nil {
		return fmt.Errorf("malformatted skid: %w", err)
	}

	skidpkt, err := pktoken.FromJSON(skidDecoded)
	if err != nil {
		return fmt.Errorf("failed to parse PK Token from Subject Key ID in x509 cert: %w", err)
	}

	fmt.Println("Cert skid PK Token Payload: ", string(skidpkt.Payload))

	err = skidpkt.VerifyCicSig()
	if err != nil {
		return fmt.Errorf("cic verification failed in  PK Token from Subject Key ID in x509 cert: %w", err)
	}

	fmt.Println("Cert: ", string(certBytes))
	return nil
}

func caKeyGen() error {
	ca := &parties.Ca{}
	err := ca.KeyGen(fpCaCfg, keyAlgorithm.String())
	if err != nil {
		return fmt.Errorf("failed to generate keys for CA: %w", err)
	}
	return nil
}

func caServ() error {
	ca := &parties.Ca{}
	err := ca.Load(keyAlgorithm.String())
	if err != nil {
		return fmt.Errorf("failed to load CA state: %w", err)
	}
	ca.Serv()
	return nil
}

func sigStoreSign() {}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("OpenPubkey: command required choices are login, sign, cert, cagen, ca")
		return
	}

	command := os.Args[1]

	switch command {
	case "login":
		if err := login(); err != nil {
			fmt.Println("Error logging in: ", err)
		} else {
			fmt.Println("Login successful!")
		}
	case "sign":
		if err := googleSign("this is a test"); err != nil {
			fmt.Println("Failed to sign message: ", err)
		}
	case "cert":
		if err := googleCert(); err != nil {
			fmt.Println("Error: ", err)
		}
	case "cagen":
		if err := caKeyGen(); err != nil {
			fmt.Println("Error: ", err)
		}
	case "ca":
		if err := caServ(); err != nil {
			fmt.Println("Error: ", err)
		}
	case "sss":
		sigStoreSign()
	default:
		fmt.Println("Unrecognized command: ", command)
	}
}
