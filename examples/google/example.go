package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/parties"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
	"golang.org/x/crypto/sha3"
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

	// File names for when we save or load our pktoken and the corresponding signing key
	skFileName  = "key.pem"
	pktFileName = "pktoken.json"
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
		if err := sign(message, outputDir, keyAlgorithm, signGQ); err != nil {
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
	signer, err := util.GenKeyPair(alg)
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
	}

	pktJson, err := client.OidcAuth(signer, alg, map[string]any{"extra": "yes"}, signGQ)
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
	saveLogin(outputDir, signer.(*ecdsa.PrivateKey), pktJson)

	return nil
}

func sign(message string, outputDir string, alg jwa.KeyAlgorithm, signGq bool) error {
	signer, pkt, err := loadLogin(outputDir)
	if err != nil {
		return fmt.Errorf("failed to load client state: %w", err)
	}

	msgHashSum := sha3.Sum256([]byte(message))
	sig, err := signer.Sign(rand.Reader, msgHashSum[:], crypto.SHA256)
	if err != nil {
		return err
	}

	fmt.Println("Signed Message:", message)
	fmt.Println("Praise Sigma:", base64.StdEncoding.EncodeToString(sig))
	fmt.Println("Hash:", hex.EncodeToString(msgHashSum[:]))
	fmt.Println("Cert:")

	pktJson, err := json.Marshal(pkt)
	if err != nil {
		return err
	}

	// Pretty print our json token
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, pktJson, "", "  "); err != nil {
		return err
	}
	fmt.Println(prettyJSON.String())

	return nil
}

func googleCert(outputDir string, alg jwa.KeyAlgorithm, signGq bool) error {
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

	var skidpkt *pktoken.PKToken
	if err := json.Unmarshal(skidDecoded, skidpkt); err != nil {
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

func saveLogin(outputDir string, sk *ecdsa.PrivateKey, pktJson []byte) error {
	skFilePath := path.Join(outputDir, skFileName)
	if err := util.WriteSKFile(skFilePath, sk); err != nil {
		return err
	}

	pktFilePath := path.Join(outputDir, pktFileName)
	return os.WriteFile(pktFilePath, pktJson, 0600)
}

func loadLogin(outputDir string) (crypto.Signer, *pktoken.PKToken, error) {
	skFilePath := path.Join(outputDir, skFileName)
	key, err := util.ReadSKFile(skFilePath)
	if err != nil {
		return nil, nil, err
	}

	pktFilePath := path.Join(outputDir, pktFileName)
	pktJson, err := os.ReadFile(pktFilePath)
	if err != nil {
		return nil, nil, err
	}

	var pkt *pktoken.PKToken
	if err := json.Unmarshal(pktJson, pkt); err != nil {
		return nil, nil, err
	}

	return key, pkt, nil
}
