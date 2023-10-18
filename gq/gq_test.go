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
)

func TestProveVerify(t *testing.T) {
	oidcPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	oidcPubKey := &oidcPrivKey.PublicKey

	idToken := createOIDCToken(t, oidcPrivKey, "test")

	signerVerifier := gq.NewSignerVerifier(oidcPubKey, 256)
	gqToken, err := signerVerifier.SignJWT(idToken)
	if err != nil {
		t.Fatal(err)
	}

	ok := signerVerifier.VerifyJWT(gqToken)
	if !ok {
		t.Fatal("couldn't verify signature we just made")
	}
}

func createOIDCToken(t *testing.T, oidcPrivKey *rsa.PrivateKey, audience string) []byte {
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
		t.Fatal(err)
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
		t.Fatal(err)
	}

	return jwt
}
