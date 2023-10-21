package cert

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"

	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/mocks"
	"github.com/openpubkey/openpubkey/util"
)

func TestCertCreation(t *testing.T) {
	caBytes, caPkSk, err := GenCAKeyPair()
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

	requiredAudience := "also_me"
	pemSubCert, err := PktTox509(pktJson, caBytes, caPkSk, requiredAudience)
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

	sigma, err := pkt.CicJWSCompact()
	if err != nil {
		t.Fatal(err)
	}

	_, err = jws.Verify(sigma, jws.WithKey(jwa.ES256, certPubkey))
	if err != nil {
		t.Fatal(err)
	}

	// Test writing and reading our certificate to and from disk
	certPath := path.Join(os.TempDir(), "cert.pem")
	err = util.WriteCertFile(certPath, cc.Raw)
	if err != nil {
		t.Fatal(err)
	}

	readCert, err := util.ReadCertFile(certPath)
	if err != nil {
		t.Fatal(err)
	}

	if string(cc.Raw) != string(readCert.Raw) {
		t.Fatal(fmt.Errorf("did not read in same certificate as we wrote to file"))
	}
}
