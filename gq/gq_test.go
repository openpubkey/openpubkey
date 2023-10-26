package gq_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/util"
)

func TestProveVerify(t *testing.T) {
	oidcPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	oidcPubKey := &oidcPrivKey.PublicKey

	idToken, err := createOIDCToken(oidcPrivKey, "test")
	if err != nil {
		t.Fatal(err)
	}

	signerVerifier := gq.NewSignerVerifier(oidcPubKey, 256)
	gqToken, err := signerVerifier.SignJWT(idToken)
	if err != nil {
		t.Fatal(err)
	}

	ok := signerVerifier.VerifyJWT(gqToken)
	if !ok {
		t.Fatal("signature verification failed")
	}
}

func TestVerifyModifiedIdPayload(t *testing.T) {
	oidcPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	oidcPubKey := &oidcPrivKey.PublicKey

	idToken, err := createOIDCToken(oidcPrivKey, "test")
	if err != nil {
		t.Fatal(err)
	}

	// modify the ID Token payload to detect IdP signature invalidity via GQ verify
	err = modifyTokenPayload(idToken, "fail")
	if err != nil {
		t.Fatal(err)
	}

	signerVerifier := gq.NewSignerVerifier(oidcPubKey, 256)
	gqToken, err := signerVerifier.SignJWT(idToken)
	if err != nil {
		t.Fatal(err)
	}

	ok := signerVerifier.VerifyJWT(gqToken)
	if ok {
		t.Fatal("signature verification passed for invalid payload")
	}
}

func TestVerifyModifiedGqPayload(t *testing.T) {
	oidcPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	oidcPubKey := &oidcPrivKey.PublicKey

	idToken, err := createOIDCToken(oidcPrivKey, "test")
	if err != nil {
		t.Fatal(err)
	}

	signerVerifier := gq.NewSignerVerifier(oidcPubKey, 256)
	gqToken, err := signerVerifier.SignJWT(idToken)
	if err != nil {
		t.Fatal(err)
	}

	// modify the ID Token payload to detect GQ signature invalidity
	err = modifyTokenPayload(gqToken, "fail")
	if err != nil {
		t.Fatal(err)
	}

	ok := signerVerifier.VerifyJWT(gqToken)
	if ok {
		t.Fatal("signature verification passed for invalid payload")
	}
}

func modifyTokenPayload(token []byte, audience string) error {
	_, payload, _, err := jws.SplitCompact(token)
	if err != nil {
		return err
	}
	newPayload := map[string]any{
		"sub": "1",
		"iss": "test",
		"aud": audience,
		"iat": time.Now().Unix(),
	}
	modifiedPayload, err := json.Marshal(newPayload)
	if err != nil {
		return err
	}
	copy(payload, util.Base64EncodeForJWT(modifiedPayload))
	return nil
}

func createOIDCToken(oidcPrivKey *rsa.PrivateKey, audience string) ([]byte, error) {
	alg := jwa.RS256 // RSASSA-PKCS-v1.5 using SHA-256

	oidcHeader := jws.NewHeaders()
	oidcHeader.Set("alg", alg.String())
	oidcHeader.Set("typ", "JWT")

	oidcPayload := map[string]any{
		"sub": "1",
		"iss": "test",
		"aud": audience,
		"iat": time.Now().Unix(),
	}
	payloadBytes, err := json.Marshal(oidcPayload)
	if err != nil {
		return nil, err
	}

	jwt, err := jws.Sign(
		payloadBytes,
		jws.WithKey(
			alg,
			oidcPrivKey,
			jws.WithProtectedHeaders(oidcHeader),
		),
	)
	if err != nil {
		return nil, err
	}

	return jwt, nil
}
