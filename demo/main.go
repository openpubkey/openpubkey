package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"github.com/openpubkey/openpubkey/pktoken/mocks"
	"github.com/openpubkey/openpubkey/signer"
)

var (
	generate  bool
	outputDir string
)

// Simple PK Token CLI mostly for demo or testing purposes
func main() {
	parseFlags()

	if generate {
		signer, err := signer.NewECDSASigner()
		if err != nil {
			fmt.Printf("Failed to generate new ECDSA key pair: %s\n", err)
			return
		}

		pkt, err := mocks.GenerateMockPKToken(signer)
		if err != nil {
			fmt.Printf("Failed to generate new PK Token: %s\n", err)
			return
		}

		pktJson, err := pkt.ToJSON()
		if err != nil {
			fmt.Printf("Encountered an error while trying to convert our PK Token to JSON: %s\n", err)
			return
		}

		// Figure out if we're printing or saving
		if outputDir == "" {
			// pretty print our fake token
			var prettyJSON bytes.Buffer
			if err := json.Indent(&prettyJSON, pktJson, "", "    "); err != nil {
				fmt.Printf("Our PK Token doesn't want to be pretty: %s\n", err)
				return
			}

			fmt.Println(prettyJSON.String())
		} else {
			pktFileName := "pktoken"
			secretKeyFileName := "pktoken.sk"

			pktFilePath := path.Join(outputDir, pktFileName)
			skFilePath := path.Join(outputDir, secretKeyFileName)

			if err := ioutil.WriteFile(pktFilePath, pktJson, os.ModePerm); err != nil {
				fmt.Printf("Unable to write to file %s: %s\n", pktFilePath, err)
				return
			}

			// Pem-encode our secret key and write it to a file
			privateKey := signer.SigningKey().(*ecdsa.PrivateKey)
			privBytes, err := x509.MarshalECPrivateKey(privateKey)
			if err != nil {
				fmt.Printf("Error marshaling ECDSA private key:%s\n", err)
				return
			}

			privPEM := &pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: privBytes,
			}

			if err := ioutil.WriteFile(skFilePath, pem.EncodeToMemory(privPEM), os.ModePerm); err != nil {
				fmt.Printf("Error writing signing key to file: %s\n", err)
				return
			}
		}
	}
}

func parseFlags() {
	flag.BoolVar(&generate, "generate", false, "Allows you to generate a single PK Token and writes value to stdout")
	flag.StringVar(&outputDir, "outputDir", "", "[optional] will write your generated values to a file in the provided directory")

	flag.Parse()
}
