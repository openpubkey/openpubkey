package mfa

import (
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/mocks"
	"github.com/openpubkey/openpubkey/util"
)

type MockAuthenticator struct {
}

func (m MockAuthenticator) Authenticate(pkt *pktoken.PKToken) error {
	return nil
}

func (m MockAuthenticator) URI() string {
	return "https://example.com"
}

func TestSimpleCosigner(t *testing.T) {

	// Generate the key pair for our cosigner
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	if err != nil {
		t.Error(err)
	}
	kid := "test-kid"
	cosignerURI := "https://example.com/mfacosigner"

	authenticator := MockAuthenticator{}

	cos, err := NewCosigner(signer, alg, cosignerURI, kid, authenticator)
	if err != nil {
		t.Error(err)
	}

	email := "arthur.aardvark@example.com"
	pkt, err := mocks.GenerateMockPKTokenWithEmail(signer, alg, email)
	if err != nil {
		t.Fatal(err)
	}

	err = cos.Cosign(pkt)
	if err != nil {
		t.Error(err)
	}

	err = cos.Cosign(pkt)
	if err != nil {
		t.Error(err)
	}

	err = cos.Cosign(pkt)
	if err != nil {
		t.Error(err)
	}
}
