package cert

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/openpubkey/openpubkey/pktoken"
)

// CreateX509Cert generates a self-signed x509 cert from a PK token
//   - OP 'sub' claim is mapped to the CN and SANs fields
//   - User public key is mapped to the RawSubjectPublicKeyInfo field
//   - Raw PK token is mapped to the SubjectKeyId field
func CreateX509Cert(pkToken *pktoken.PKToken, signer crypto.Signer) ([]byte, error) {
	pkTokenJSON, err := json.Marshal(pkToken)
	if err != nil {
		return nil, fmt.Errorf("error marshalling PK token to JSON: %w", err)
	}

	// get subject identitifer from pk token
	var payload struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(pkToken.Payload, &payload); err != nil {
		return nil, err
	}

	// encode ephemeral public key
	ecPub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("error marshalling public key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber:            big.NewInt(1),
		Subject:                 pkix.Name{CommonName: payload.Subject},
		RawSubjectPublicKeyInfo: ecPub,
		NotBefore:               time.Now(),
		NotAfter:                time.Now().Add(365 * 24 * time.Hour), // valid for 1 year
		KeyUsage:                x509.KeyUsageDigitalSignature,
		ExtKeyUsage:             []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid:   true,
		DNSNames:                []string{payload.Subject},
		IsCA:                    false,
		SubjectKeyId:            pkTokenJSON,
	}

	// create a self-signed X.509 certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("error creating X.509 certificate: %w", err)
	}
	certBlock := &pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	return pem.EncodeToMemory(certBlock), nil
}
