package ca

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/sirupsen/logrus"

	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
)

type Ca struct {
	pksk        *ecdsa.PrivateKey
	Alg         jwa.KeyAlgorithm
	CaCertBytes []byte
	cfgPath     string
	provider    client.OpenIdProvider
}

func (a *Ca) KeyGen(cfgPath string, alg string) error {
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
			StreetAddress: []string{"Anon Anon St."},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &a.pksk.PublicKey, a.pksk)
	if err != nil {
		return err
	}
	a.CaCertBytes = caBytes

	a.cfgPath = cfgPath
	err = os.MkdirAll(a.cfgPath, os.ModePerm)
	if err != nil {
		return err
	}
	fpCaCert := path.Join(a.cfgPath, "ca-cert.pub")
	fpCaPk := path.Join(a.cfgPath, "ca.pub")
	fpCaSk := path.Join(a.cfgPath, "ca.sk")

	err = util.WriteCertFile(fpCaCert, a.CaCertBytes)
	if err != nil {
		return err
	}

	err = util.WritePKFile(fpCaPk, &a.pksk.PublicKey)
	if err != nil {
		return err
	}

	err = util.WriteSKFile(fpCaSk, a.pksk)
	if err != nil {
		return err
	}

	return nil
}

func (a *Ca) Load(alg string) error {
	a.Alg = jwa.KeyAlgorithmFrom(alg)

	fpCaCert := path.Join(a.cfgPath, "ca-cert.pub")
	fpCaSk := path.Join(a.cfgPath, "ca.sk")

	pksk, err := util.ReadSKFile(fpCaSk)
	if err != nil {
		return err
	}

	CaCertBytes, err := util.ReadCertFile(fpCaCert)
	if err != nil {
		return err
	}

	a.pksk = pksk
	a.CaCertBytes = CaCertBytes.Raw

	return nil
}

type OpkCa struct {
	RequiredAudience string
}

func (a *Ca) Serv() {
	port := "3002"

	issueCertAuthHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		params := r.URL.Query()
		pktCom := []byte(params["pkt"][0])

		pktX509, err := a.PktTox509(pktCom, a.CaCertBytes)
		if err != nil {
			rerr := fmt.Errorf("error creating x509 for PK Token: %v", err)
			w.Header().Set("Error", rerr.Error())
			http.Error(w, rerr.Error(), http.StatusInternalServerError)
			return
		}

		w.Write(pktX509)
	})

	http.Handle("/cert", issueCertAuthHandler)

	lis := fmt.Sprintf("localhost:%s", port)
	logrus.Infof("listening on http://%s/", lis)
	logrus.Info("press ctrl+c to stop")
	logrus.Fatal(http.ListenAndServe(lis, nil))
}

func (a *Ca) PktTox509(pktCom []byte, caBytes []byte) ([]byte, error) {
	pkt := new(pktoken.PKToken)
	if err := json.Unmarshal(pktCom, pkt); err != nil {
		return nil, err
	}

	if err := pkt.VerifyCicSig(); err != nil {
		return nil, err
	}

	payload := new(client.OidcClaims)
	if err := json.Unmarshal(pkt.Payload, payload); err != nil {
		return nil, err
	}

	err := client.VerifyPKToken(context.Background(), pkt, a.provider)
	if err != nil {
		return nil, fmt.Errorf("error PK token is not valid: %w", err)
	}

	caTemplate, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, err
	}

	// Based on template from https://github.com/sigstore/fulcio/blob/3c8fbea99c71fedfe47d39e12159286eb443a917/pkg/test/cert_utils.go#L195
	subTemplate := &x509.Certificate{
		SerialNumber:   big.NewInt(1),
		EmailAddresses: []string{payload.Email},
		NotBefore:      time.Now().Add(-1 * time.Minute),
		NotAfter:       time.Now().Add(time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		IsCA:           false,
		ExtraExtensions: []pkix.Extension{{
			// OID for OIDC Issuer extension
			Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1},
			Critical: false,
			Value:    []byte(payload.Issuer),
		}},
		SubjectKeyId: []byte(pktCom),
	}

	// subPkSk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// if err != nil {
	// 	return nil, err
	// }

	// subPkSk.PublicKey()

	cic, err := pkt.GetCicValues()
	if err != nil {
		return nil, err
	}

	upk := cic.PublicKey()

	// fmt.Println("In CA Pkt :"+ pkt.)

	var rawkey interface{} // This is the raw key, like *rsa.PrivateKey or *ecdsa.PrivateKey
	if err := upk.Raw(&rawkey); err != nil {
		return nil, err
	}

	subCertBytes, err := x509.CreateCertificate(rand.Reader, subTemplate, caTemplate, rawkey, a.pksk)
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
