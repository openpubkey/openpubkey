package cosigner

import (
	"crypto"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/mocks"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestAuthIDs(t *testing.T) {
	cosAlg := jwa.ES256
	cosSigner, err := util.GenKeyPair(cosAlg)
	if err != nil {
		t.Error(err)
	}
	hmacKey := []byte{0x1, 0x2, 0x3}

	cos := AuthCosigner{
		Cosigner: Cosigner{
			Alg:    cosAlg,
			Signer: cosSigner,
		},
		Issuer:       "https://example.com",
		KeyID:        "kid1234",
		authIdIter:   atomic.Uint64{},
		hmacKey:      hmacKey,
		AuthStateMap: make(map[string]*AuthState),
		AuthCodeMap:  make(map[string]string),
	}

	// Test if we get the same value if we supply exact the same time
	unixTime := uint64(5)
	authID1, err := cos.CreateAuthID(unixTime)
	if err != nil {
		t.Fatal(err)
	}

	authID2, err := cos.CreateAuthID(unixTime)
	if err != nil {
		t.Fatal(err)
	}
	require.NotEqualValues(t, authID1, authID2)

	require.Equal(t, "644117927902f52d3949804c7ce417509d9437eb1240a9bf75725c9f61d5b424", authID1)
	require.Equal(t, "f7d16adcef9f7d0e72139f0edae98db64c2db1f0cb8b59468d4766e91126f4eb", authID2)
}

func TestInitAuth(t *testing.T) {
	cos := CreateAuthCosigner(t)

	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	if err != nil {
		t.Error(err)
	}
	pkt, err := mocks.GenerateMockPKToken(signer, alg)
	if err != nil {
		t.Fatal(err)
	}

	cosP := client.CosignerProvider{
		Issuer:       "example.com",
		CallbackPath: "/mfaredirect",
	}
	redirectURI := fmt.Sprintf("%s/%s", "http://localhost:5555", cosP.CallbackPath)

	initAuthMsgJson, _, err := cosP.CreateInitAuthSig(redirectURI)
	sig, err := pkt.NewSignedMessage(initAuthMsgJson, signer)
	authID1, err := cos.InitAuth(pkt, sig)
	if err != nil {
		t.Error(err)
	}
	require.NotEmpty(t, authID1)

	emptySig := []byte{}
	authID2, err := cos.InitAuth(pkt, emptySig)
	require.ErrorContains(t, err, "failed to parse sig")
	require.Empty(t, authID2)
}

func TestRedeemAuthcode(t *testing.T) {
	cos := CreateAuthCosigner(t)

	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	if err != nil {
		t.Error(err)
	}
	pkt, err := mocks.GenerateMockPKToken(signer, alg)
	if err != nil {
		t.Fatal(err)
	}

	cosP := client.CosignerProvider{
		Issuer:       "example.com",
		CallbackPath: "/mfaredirect",
	}
	redirectURI := fmt.Sprintf("%s/%s", "http://localhost:5555", cosP.CallbackPath)

	diffSigner, err := util.GenKeyPair(alg)
	if err != nil {
		t.Error(err)
	}
	diffPkt, err := mocks.GenerateMockPKToken(diffSigner, alg)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		pkt    *pktoken.PKToken
		signer crypto.Signer

		wantError bool
	}{
		{pkt: pkt, signer: signer, wantError: false},
		{pkt: pkt, signer: diffSigner, wantError: true},
		{pkt: diffPkt, signer: diffSigner, wantError: false},
		{pkt: diffPkt, signer: signer, wantError: true},
	}

	for i, tc := range tests {
		initAuthMsgJson, _, err := cosP.CreateInitAuthSig(redirectURI)
		sig, err := tc.pkt.NewSignedMessage(initAuthMsgJson, tc.signer)
		authID, err := cos.InitAuth(tc.pkt, sig)
		if !tc.wantError && err != nil {
			t.Fatalf("test %d: expected: nil, got: %v", i+1, err)
		}
		authcode, err := cos.NewAuthcode(authID)

		acSig, err := tc.pkt.NewSignedMessage([]byte(authcode), tc.signer)
		if err != nil {
			t.Fatalf("test %d: expected: nil, got: %v", i+1, err)
		}

		cosSig, err := cos.RedeemAuthcode(acSig)
		if tc.wantError {
			if err == nil {
				t.Fatalf("test %d: expected error, got: %v", i+1, err)
			}
		} else {
			if err != nil {
				t.Fatalf("test %d: expected: nil, got: %v", i+1, err)
			}
			if cosSig == nil {
				t.Fatalf("test %d: expected not nil, got: %v", i+1, cosSig)
			}
		}
	}
}

func TestCanOnlyRedeemAuthcodeOnce(t *testing.T) {
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	pkt, err := mocks.GenerateMockPKToken(signer, alg)
	if err != nil {
		t.Fatal(err)
	}

	cos := CreateAuthCosigner(t)

	cosP := client.CosignerProvider{
		Issuer:       "example.com",
		CallbackPath: "/mfaredirect",
	}
	redirectURI := fmt.Sprintf("%s/%s", "http://localhost:5555", cosP.CallbackPath)

	// reuse the same authcode twice, it should fail
	initAuthMsgJson, _, err := cosP.CreateInitAuthSig(redirectURI)
	sig, err := pkt.NewSignedMessage(initAuthMsgJson, signer)
	authID, err := cos.InitAuth(pkt, sig)
	require.Empty(t, err)

	authcode, err := cos.NewAuthcode(authID)
	require.Empty(t, err)

	acSig1, err := pkt.NewSignedMessage([]byte(authcode), signer)
	require.Empty(t, err)

	acSig2, err := pkt.NewSignedMessage([]byte(authcode), signer)
	require.Empty(t, err)

	cosSig, err := cos.RedeemAuthcode(acSig1)
	require.NotEmpty(t, cosSig)
	require.Empty(t, err)

	// Should fail because authcode has already been issued
	cosSig, err = cos.RedeemAuthcode(acSig2)
	require.Empty(t, cosSig)
	require.ErrorContains(t, err, "authcode has already been redeemed")
}

func TestNewAuthcodeFailure(t *testing.T) {
	cosAlg := jwa.ES256
	cosSigner, err := util.GenKeyPair(cosAlg)
	if err != nil {
		t.Error(err)
	}
	hmacKey := []byte{0x1, 0x2, 0x3}

	cos := AuthCosigner{
		Cosigner: Cosigner{
			Alg:    cosAlg,
			Signer: cosSigner,
		},
		Issuer:       "https://example.com",
		KeyID:        "kid1234",
		authIdIter:   atomic.Uint64{},
		hmacKey:      hmacKey,
		AuthStateMap: make(map[string]*AuthState),
		AuthCodeMap:  make(map[string]string),
	}

	// Ensure failure if AuthID not recorded by cosigner
	unixTime := uint64(5)
	authID, err := cos.CreateAuthID(unixTime)
	if err != nil {
		t.Fatal(err)
	}

	authcode, err := cos.NewAuthcode(authID)
	require.ErrorContains(t, err, "no such authID")
	require.Empty(t, authcode)
}

func CreateAuthCosigner(t *testing.T) *AuthCosigner {
	cosAlg := jwa.ES256
	signer, err := util.GenKeyPair(cosAlg)
	if err != nil {
		t.Error(err)
	}
	hmacKey := []byte{0x1, 0x2, 0x3}

	return &AuthCosigner{
		Cosigner: Cosigner{
			Alg:    cosAlg,
			Signer: signer,
		},
		Issuer:       "https://example.com",
		KeyID:        "kid1234",
		authIdIter:   atomic.Uint64{},
		hmacKey:      hmacKey,
		AuthStateMap: make(map[string]*AuthState),
		AuthCodeMap:  make(map[string]string),
	}
}
