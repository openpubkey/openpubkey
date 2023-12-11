package mfacosigner

import (
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
	wauthnmock "github.com/openpubkey/openpubkey/examples/mfa/mfacosigner/mocks"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/mocks"
	"github.com/openpubkey/openpubkey/util"
)

func TestFullFlow(t *testing.T) {
	// Step 0: Setup
	// Create our PK Token and signer
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	if err != nil {
		t.Error(err)
	}
	email := "arthur.aardvark@example.com"
	pkt, err := mocks.GenerateMockPKTokenWithEmail(signer, alg, email)
	if err != nil {
		t.Fatal(err)
	}

	// Create our MFA Cosigner
	cosSigner, err := util.GenKeyPair(alg)
	if err != nil {
		t.Error(err)
	}
	kid := "test-kid"
	cosignerURI := "https://example.com"
	rpID := "http://localhost"
	RPOrigin := "http://localhost"

	// WebAuthn configuration
	cfg := &webauthn.Config{
		RPDisplayName: "OpenPubkey",
		RPID:          rpID,
		RPOrigin:      RPOrigin,
	}
	cos, err := New(cosSigner, alg, cosignerURI, kid, cfg)
	if err != nil {
		t.Error(err)
	}

	// Create our MFA device
	wauthnDevice, err := wauthnmock.NewWebauthnDevice(rpID)
	if err != nil {
		t.Error(err)
	}

	// Init MFA Cosigner flow
	cosP := client.CosignerProvider{
		Issuer:      "example.com",
		RedirectURI: "https://example.com/mfaredirect",
	}

	initAuthMsgJson, _, err := cosP.CreateInitAuthSig()
	sig, err := pkt.NewSignedMessage(initAuthMsgJson, signer)
	authID, err := cos.InitAuth(pkt, sig)
	if err != nil {
		t.Fatal(err)
	}

	// Register MFA device
	createCreation, err := cos.BeginRegistration(authID)
	if err != nil {
		t.Fatal(err)
	}
	if createCreation == nil {
		t.Fatal("Expected cred creation to not be nil")
	}
	credCreationResp, err := wauthnDevice.RegResp(createCreation)
	if err != nil {
		t.Fatal(err)
	}
	err = cos.FinishRegistration(authID, credCreationResp)
	if err != nil {
		t.Fatal(err)
	}

	// Login MFA device
	credAssert, err := cos.BeginLogin(authID)
	if err != nil {
		t.Fatal(err)
	}
	loginResp, err := wauthnDevice.LoginResp(credAssert)
	if err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatal(err)
	}

	authcode, ruriRet, err := cos.FinishLogin(authID, loginResp)
	if err != nil {
		t.Fatal(err)
	}
	if credAssert == nil {
		t.Fatal("Expected cred creation to not be nil")
	}
	if ruriRet != cosP.RedirectURI {
		t.Fatalf("expected ruri to be %s but was %s", cosP.RedirectURI, ruriRet)
	}

	// Sign the authcode
	// and exchange it with the Cosigner to get the PK Token cosigned
	authcodeSig, err := pkt.NewSignedMessage([]byte(authcode), signer)
	if err != nil {
		t.Fatal(err)
	}

	cosSig, err := cos.RedeemAuthcode(authcodeSig)
	if err != nil {
		t.Fatal(err)
	}
	if cosSig == nil {
		t.Fatal("Expected pktCos to be cosigned")
	}
	pkt.AddSignature(cosSig, pktoken.Cos)
}
