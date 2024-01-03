package ca

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"

	"github.com/openpubkey/openpubkey/client/providers"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/mocks"
	"github.com/openpubkey/openpubkey/util"
)

func TestCACertCreation(t *testing.T) {
	// create a temporary directory
	tempDir, err := os.MkdirTemp("", "TestCACertCreation")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	provider, err := providers.NewMockOpenIdProvider()
	if err != nil {
		t.Fatal(err)
	}

	ca := Ca{
		cfgPath:  tempDir,
		provider: provider,
	}

	err = ca.KeyGen(tempDir, string(jwa.ES256))
	if err != nil {
		t.Fatal(err)
	}

	userAlg := jwa.ES256
	userSigningKey, err := util.GenKeyPair(userAlg)
	if err != nil {
		t.Fatal(err)
	}

	mockPkt, err := mocks.GenerateMockPKToken(userSigningKey, userAlg)
	if err != nil {
		t.Fatal(err)
	}

	pktJson, err := json.Marshal(mockPkt)
	if err != nil {
		t.Fatal(err)
	}

	pemSubCert, err := ca.PktTox509(pktJson, ca.CaCertBytes)
	if err != nil {
		t.Fatal(err)
	}

	decodeBlock, _ := pem.Decode(pemSubCert)

	cc, err := x509.ParseCertificate(decodeBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	certPubkey := cc.PublicKey.(*ecdsa.PublicKey)

	var pkt *pktoken.PKToken
	if err := json.Unmarshal(pktJson, &pkt); err != nil {
		t.Fatal(err)
	}

	sigma, err := pkt.Compact(pkt.Cic)
	if err != nil {
		t.Fatal(err)
	}

	_, err = jws.Verify(sigma, jws.WithKey(jwa.ES256, certPubkey))
	if err != nil {
		t.Fatal(err)
	}

	// Test reading our certificate from disk
	testCa := Ca{
		cfgPath: tempDir,
	}
	err = testCa.Load(string(jwa.ES256))
	if err != nil {
		t.Fatal(err)
	}

	if string(ca.CaCertBytes) != string(testCa.CaCertBytes) {
		t.Fatal("failed reading CA cert bytes from disk")
	}

	ecPub, err := x509.MarshalPKIXPublicKey(ca.pksk.Public())
	if err != nil {
		t.Fatal(err)
	}
	testEcPub, err := x509.MarshalPKIXPublicKey(testCa.pksk.Public())
	if err != nil {
		t.Fatal(err)
	}

	if string(ecPub) != string(testEcPub) {
		t.Fatal("failed reading pksk from disk")
	}

}
