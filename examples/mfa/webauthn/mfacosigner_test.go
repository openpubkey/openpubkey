package webauthn

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/mocks"
	"github.com/openpubkey/openpubkey/util"
)

func TestInitAuth(t *testing.T) {

	// Generate the key pair for our cosigner
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	if err != nil {
		t.Error(err)
	}
	kid := "test-kid"
	cosignerURI := "https://example.com/mfacosigner"

	cos, err := NewCosigner(signer, alg, cosignerURI, kid)
	if err != nil {
		t.Error(err)
	}

	email := "arthur.aardvark@example.com"
	pkt, err := mocks.GenerateMockPKTokenWithEmail(signer, alg, email)
	if err != nil {
		t.Fatal(err)
	}

	ruri := "https://example.com/mfaredirect"
	msg := InitMFAAuth{
		RedirectUri: ruri,
		TimeSigned:  time.Now().Unix(),
	}
	msgJson, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := pkt.NewSignedMessage(msgJson, signer)
	authID, err := cos.InitAuth(pkt, sig)
	if err != nil {
		t.Fatal(err)
	}

	authcode, err := cos.NewAuthcode(authID)
	if err != nil {
		t.Fatal(err)
	}

	authcodeSig, err := pkt.NewSignedMessage(authcode, signer)

	pktCosB64, err := cos.CheckAuthcode(authcode, authcodeSig)
	if err != nil {
		t.Fatal(err)
	}

	pktCosJson, err := util.Base64DecodeForJWT(pktCosB64)
	if err != nil {
		t.Fatal(err)
	}

	var pktCos pktoken.PKToken
	err = json.Unmarshal(pktCosJson, &pktCos)
	if err != nil {
		t.Fatal(err)
	}
	if pktCos.Cos == nil {
		t.Fatal("Expected pktCos to be cosigned")
	}
}
