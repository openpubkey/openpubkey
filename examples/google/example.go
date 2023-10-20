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

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/parties"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
)

// Variables for building our google provider
var (
	clientID = "184968138938-g1fddl5tglo7mnlbdak8hbsqhhf79f32.apps.googleusercontent.com"
	// The clientSecret was intentionally checked in for the purposes of this example,. It holds no power. Do not report as a security issue
	clientSecret = "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" // Google requires a ClientSecret even if this a public OIDC App
	issuer       = "https://accounts.google.com"
	scopes       = []string{"openid profile email"}
	redirURIPort = "3000"
	callbackPath = "/login-callback"
	redirectURI  = fmt.Sprintf("http://localhost:%v%v", redirURIPort, callbackPath)
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("OpenPubkey: command choices are login, sign, and cert")
		return
	}

	signGQ := true
	keyAlgorithm := jwa.ES256

	// Directory for saving data
	outputDir := "opk/google"

	command := os.Args[1]
	switch command {
	case "login":
		if err := login(outputDir, keyAlgorithm, signGQ); err != nil {
			fmt.Println("Error logging in:", err)
		} else {
			fmt.Println("Login successful!")
		}
	case "sign":
		message := "sign me!!"
		if err := googleSign(message, outputDir, keyAlgorithm, signGQ); err != nil {
			fmt.Println("Failed to sign test message:", err)
		}
	case "cert":
		if err := googleCert(outputDir, keyAlgorithm, signGQ); err != nil {
			fmt.Println("Failed to generate certificate:", err)
		}
	default:
		fmt.Println("Unrecognized command:", command)
	}
}

func login(outputDir string, alg jwa.KeyAlgorithm, signGQ bool) error {
	signer, err := pktoken.NewSigner(outputDir, alg.String(), signGQ, map[string]any{"extra": "yes"})
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

func googleSign(message string, outputDir string, alg jwa.KeyAlgorithm, signGq bool) error {
	signer, err := pktoken.LoadFromFile(outputDir, alg.String(), signGq, nil)
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

	fmt.Println("Signed Message:", message)
	fmt.Println("Praise Sigma:", base64.StdEncoding.EncodeToString(rawSigma))
	fmt.Println("Hash:", hex.EncodeToString(msgHashSum))
	fmt.Println("Cert:")

	// Pretty print our json token
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, signer.PktJson, "", "  "); err != nil {
		return err
	}

	fmt.Println(prettyJSON.String())

	return nil
}

func googleCert(outputDir string, alg jwa.KeyAlgorithm, signGq bool) error {
	signer, err := pktoken.LoadFromFile(outputDir, alg.String(), false, nil)
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
		return err
	}
	fmt.Println("Cert received:", string(certBytes))

	block, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse cert: %s", err)
	}

	skid := cert.SubjectKeyId

	fmt.Println("Cert skid:", string(skid))

	skidDecoded, err := util.Base64DecodeForJWT(skid)
	if err != nil {
		return fmt.Errorf("malformatted skid: %w", err)
	}

	skidpkt, err := pktoken.FromJSON(skidDecoded)
	if err != nil {
		return fmt.Errorf("failed to extract PK Token from x509 cert: %w", err)
	}

	fmt.Println("Cert skid PK Token payload:", string(skidpkt.Payload))

	err = skidpkt.VerifyCicSig()
	if err != nil {
		return fmt.Errorf("cic verification failed in PK Token: %w", err)
	}

	fmt.Println("Cert:", string(certBytes))
	return nil
}
