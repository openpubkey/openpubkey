// Copyright 2024 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"

	"github.com/openpubkey/openpubkey/cert"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/pktoken"
)

type Ca struct {
	pksk *ecdsa.PrivateKey
	Alg  jwa.KeyAlgorithm
	// CaCertBytes []byte
	RootCertPem []byte
	op          client.OpenIdProvider
}

func New(op client.OpenIdProvider) (*Ca, error) {
	ca := Ca{
		op: op,
	}
	alg := string(jwa.ES256)
	err := ca.KeyGen(alg)
	if err != nil {
		return nil, err
	}

	return &ca, nil
}

func (a *Ca) KeyGen(alg string) error {
	a.Alg = jwa.KeyAlgorithmFrom(alg)

	pksk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	a.pksk = pksk

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Openpubkey-test-ca-cert"},
			Country:       []string{"International"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{"255 Test St."},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageCodeSigning},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &a.pksk.PublicKey, a.pksk)
	if err != nil {
		return err
	}

	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	a.RootCertPem = caPEM.Bytes()

	return nil
}

func (a *Ca) CheckPKToken(pktJson []byte) (*pktoken.PKToken, error) {
	pkt := new(pktoken.PKToken)
	if err := json.Unmarshal(pktJson, pkt); err != nil {
		return nil, err
	}

	if err := pkt.VerifyCicSig(); err != nil {
		return nil, err
	}

	err := client.VerifyPKToken(context.Background(), pkt, a.op)
	if err != nil {
		return nil, fmt.Errorf("error PK Token is not valid: %w", err)
	}

	return pkt, nil
}

func (a *Ca) PktToSignedX509(pktJson []byte) ([]byte, error) {
	pkt, err := a.CheckPKToken(pktJson)
	if err != nil {
		return nil, err
	}

	pktUpk, err := ExtractRawPubkey(pkt)
	if err != nil {
		return nil, err
	}

	subTemplate, err := cert.PktToX509Template(pkt)
	if err != nil {
		return nil, err
	}

	rootCert, _ := pem.Decode(a.RootCertPem)
	if rootCert == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}
	caTemplate, err := x509.ParseCertificate(rootCert.Bytes)
	if err != nil {
		return nil, err
	}

	subCertBytes, err := x509.CreateCertificate(rand.Reader, subTemplate, caTemplate, pktUpk, a.pksk)
	if err != nil {
		return nil, err
	}

	subCert, err := x509.ParseCertificate(subCertBytes)
	if err != nil {
		return nil, err
	}

	var pemSubCert bytes.Buffer
	err = pem.Encode(&pemSubCert, &pem.Block{Type: "CERTIFICATE", Bytes: subCert.Raw})
	if err != nil {
		return nil, err
	}
	return pemSubCert.Bytes(), nil
}

// VerifyPktCert checks that the X509 cert is signed by the CA and that
// the PK Token in the cert matches the public key in the cert.
func (a *Ca) VerifyPktCert(issuedCertPEM []byte) error {

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(a.RootCertPem))
	if !ok {
		return fmt.Errorf("failed to parse root certificate")
	}

	block, _ := pem.Decode([]byte(issuedCertPEM))
	if block == nil {
		return fmt.Errorf("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate PEM: %w", err)
	}
	_, err = cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	})
	if err != nil {
		return fmt.Errorf("failed to verify certificate: %w", err)
	}

	pktJson := cert.SubjectKeyId
	pkt := new(pktoken.PKToken)
	if err := json.Unmarshal(pktJson, pkt); err != nil {
		return err
	}
	pktUpk, err := ExtractRawPubkey(pkt)
	if err != nil {
		return err
	}

	certPublickey := cert.PublicKey.(*ecdsa.PublicKey)
	if !certPublickey.Equal(pktUpk) {
		return fmt.Errorf("public key in cert does not match PK Token's public key")
	}

	certPublicKeyBytes, err := x509.MarshalPKIXPublicKey(certPublickey)
	if err := json.Unmarshal(pktJson, pkt); err != nil {
		return err
	}
	if string(cert.RawSubjectPublicKeyInfo) != string(certPublicKeyBytes) {
		return fmt.Errorf("certificate raw subject public key info does not match ephemeral public key")
	}

	// Verification succeeds
	return nil
}

func ExtractRawPubkey(pkt *pktoken.PKToken) (interface{}, error) {
	cic, err := pkt.GetCicValues()
	if err != nil {
		return nil, err
	}
	upk := cic.PublicKey()
	var rawUpk interface{} // This is the raw key, like *rsa.PrivateKey or *ecdsa.PrivateKey
	if err := upk.Raw(&rawUpk); err != nil {
		return nil, err
	}
	return rawUpk, nil
}
