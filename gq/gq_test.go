package gq

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/util"
)

func TestSignVerifyJWT(t *testing.T) {
	oidcPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	oidcPubKey := &oidcPrivKey.PublicKey

	idToken, err := createOIDCToken(oidcPrivKey, "test")
	if err != nil {
		t.Fatal(err)
	}

	signerVerifier, err := NewSignerVerifier(oidcPubKey, 256)
	if err != nil {
		t.Fatal(err)
	}

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
	modifiedToken, err := modifyTokenPayload(idToken, "fail")
	if err != nil {
		t.Fatal(err)
	}
	_, err = jws.Verify(modifiedToken, jws.WithKey(jwa.RS256, oidcPubKey))
	if err == nil {
		t.Fatal("ID token signature should fail for modified token")
	}
	signerVerifier, err := NewSignerVerifier(oidcPubKey, 256)
	if err != nil {
		t.Fatal(err)
	}
	gqToken, err := signerVerifier.SignJWT(modifiedToken)
	if err != nil {
		t.Fatal(err)
	}

	ok := signerVerifier.VerifyJWT(gqToken)
	if ok {
		t.Fatal("GQ signature verification passed for invalid payload")
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

	signerVerifier, err := NewSignerVerifier(oidcPubKey, 256)
	if err != nil {
		t.Fatal(err)
	}
	gqToken, err := signerVerifier.SignJWT(idToken)
	if err != nil {
		t.Fatal(err)
	}

	// modify the ID Token payload to detect GQ signature invalidity
	modifiedToken, err := modifyTokenPayload(gqToken, "fail")
	if err != nil {
		t.Fatal(err)
	}

	ok := signerVerifier.VerifyJWT(modifiedToken)
	if ok {
		t.Fatal("GQ signature verification passed for invalid payload")
	}
}

func modifyTokenPayload(token []byte, audience string) ([]byte, error) {
	headers, _, signature, err := jws.SplitCompact(token)
	if err != nil {
		return nil, err
	}
	newPayload := map[string]any{
		"sub": "1",
		"iss": "test",
		"aud": audience,
		"iat": time.Now().Unix(),
	}
	modifiedPayload, err := json.Marshal(newPayload)
	if err != nil {
		return nil, err
	}
	newToken := util.JoinJWTSegments(headers, util.Base64EncodeForJWT(modifiedPayload), signature)
	return newToken, nil
}

func createOIDCToken(oidcPrivKey *rsa.PrivateKey, audience string) ([]byte, error) {
	alg := jwa.RS256 // RSASSA-PKCS-v1.5 using SHA-256

	oidcHeader := jws.NewHeaders()
	err := oidcHeader.Set(jws.AlgorithmKey, alg)
	if err != nil {
		return nil, err
	}
	err = oidcHeader.Set(jws.TypeKey, "JWT")
	if err != nil {
		return nil, err
	}

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
