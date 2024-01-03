package cert

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/client/providers"
	"github.com/openpubkey/openpubkey/util"
)

func TestCreateX509Cert(t *testing.T) {
	// generate pktoken
	signer, err := util.GenKeyPair(jwa.ES256)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := providers.NewMockOpenIdProvider()
	if err != nil {
		t.Fatal(err)
	}
	opkClient := client.OpkClient{Op: provider}
	pkToken, err := opkClient.OidcAuth(context.Background(), signer, jwa.ES256, map[string]any{}, true)
	if err != nil {
		t.Fatal(err)
	}

	// create x509 cert from pk token
	cert, err := CreateX509Cert(pkToken, signer)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := pem.Decode(cert)
	result, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	// test cert SubjectKeyId field contains PK token
	pkTokenJSON, err := json.Marshal(pkToken)
	if err != nil {
		t.Fatal(err)
	}
	if string(result.SubjectKeyId) != string(pkTokenJSON) {
		t.Fatal("certificate subject key id does not match PK token")
	}

	// test cert RawSubjectPublicKeyInfo field contains ephemeral public key
	ecPub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	if string(result.RawSubjectPublicKeyInfo) != string(ecPub) {
		t.Fatal("certificate raw subject public key info does not match ephemeral public key")
	}

	// test cert common name == pktoken sub claim
	var payload struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(pkToken.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if result.Subject.CommonName != payload.Subject {
		t.Fatal("cert common name does not equal pk token sub claim")
	}
}
