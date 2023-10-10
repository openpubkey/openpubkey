package main

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/zitadel/oidc/v2/pkg/oidc"

	"github.com/openpubkey/openpubkey/parties"
	"github.com/openpubkey/openpubkey/pktoken"
)

// TODO: Create nice golang services rather than just using this handler nonsense

type ReceiveIDTHandler func(tokens *oidc.Tokens[*oidc.IDTokenClaims])

func GoogleSign() {
	signer, err := pktoken.LoadFromFile(fpClientCfg, "ES256", false, nil)
	if err != nil {
		logrus.Fatalf("Error loading client state: %s", err.Error())
		return
	}

	client := &parties.OpkClient{
		Signer: signer,
		Op: &parties.GoogleOp{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Issuer:       issuer,
			Scopes:       scopes,
			RedirURIPort: redirURIPort,
			CallbackPath: callbackPath,
			RedirectURI:  redirectURI,
		},
	}

	msg, err := os.ReadFile("hunter.txt")
	if err != nil {
		panic(err)
	}

	msgHash := sha256.New()
	_, err = msgHash.Write(msg)
	if err != nil {
		panic(err)
	}
	msgHashSum := msgHash.Sum(nil)
	hashhex := hex.EncodeToString(msgHashSum)

	rawSigma, err := client.Signer.Pksk.Sign(rand.Reader, msgHashSum, crypto.SHA256)
	if err != nil {
		logrus.Fatalf("Error signing: %s", err.Error())
		return
	}

	err = os.WriteFile("sigma.sig", rawSigma, 0644)

	sigma := base64.StdEncoding.EncodeToString(rawSigma)
	if err != nil {
		panic(err)
	}
	cert, err := os.ReadFile("pkt.cert")
	if err != nil {
		panic(err)
	}

	certstr := make([]byte, base64.StdEncoding.EncodedLen(len(cert)))
	base64.StdEncoding.Encode(certstr, cert)

	fmt.Println("Praise Sigma: " + string(sigma))
	fmt.Println("Hash: " + string(hashhex))
	fmt.Println("Cert: " + string(certstr))
}

func GoogleCert() {

	signer, err := pktoken.LoadFromFile(fpClientCfg, "ES256", false, nil)
	if err != nil {
		fmt.Printf("Error loading client state: %s", err.Error())
		return
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
		fmt.Printf("Error signing: %s", err.Error())
		return
	}
	fmt.Println("Cert received: " + string(certBytes))

	block, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Printf("Error failed to parse cert: %s", err.Error())
		return
	}

	skid := cert.SubjectKeyId

	fmt.Println("Cert skid: " + string(skid))

	skidDecoded, err := base64.RawStdEncoding.DecodeString(string(skid))

	skidpkt, err := pktoken.FromJSON(skidDecoded)
	if err != nil {
		fmt.Printf("Error failed to parse PK Token from Subject Key ID in x509 cert: %s", err.Error())
		return
	}

	fmt.Println("Cert skid PK Token Payload: " + string(skidpkt.Payload))

	err = skidpkt.VerifyCicSig()
	if err != nil {
		fmt.Printf("Error CIC verification failed in  PK Token from Subject Key ID in x509 cert: %s", err.Error())
		return
	}

	fmt.Println("Cert: " + string(certBytes))

}

func CaKeyGen() {
	ca := &parties.Ca{}
	err := ca.KeyGen(fpCaCfg, "ES256")
	if err != nil {
		fmt.Printf("Error keygen: %s \n", err.Error())
		return
	}
}

func CaServ() {

	ca := &parties.Ca{}
	err := ca.Load("ES256")
	if err != nil {
		fmt.Printf("Error Loading CA state: %s \n", err.Error())
		return
	}
	ca.Serv()

}

func SigStoreSign() {}

func main() {

	fpClientCfg = "configs/clcfg"
	fpMfaCfg = "configs/mfacfg"
	fpCaCfg = "configs/cacfg"

	if len(os.Args) < 2 {
		fmt.Printf("OpenPubkey: command required choices are login, sign, cert, cagen, ca")
		return
	}

	command := os.Args[1]

	switch command {
	case "login":
		{
			opkClientAlg := "ES256"
			gq := true

			signer, err := pktoken.NewSigner(fpClientCfg, opkClientAlg, gq, map[string]any{"extra": "yes"})
			if err != nil {
				panic(err)
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

			client.OidcAuth()
		}
	case "sign":
		GoogleSign()

	case "cert":
		GoogleCert()

	case "cagen":
		CaKeyGen()

	case "ca":
		CaServ()

	case "sss":
		SigStoreSign()

	default:
		fmt.Printf("Error! No valid command")
	}
}
