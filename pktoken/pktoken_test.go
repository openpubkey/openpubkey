package pktoken_test

import (
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/jwt/openid"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/signer"
)

func TestPkToken(t *testing.T) {
	signer, err := signer.NewECDSASigner()
	if err != nil {
		t.Fatal(err)
	}

	cic, err := clientinstance.NewClaims(signer.JWKKey(), map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	// Calculate our nonce from our cic values
	nonce, err := cic.Commitment()
	if err != nil {
		t.Fatal(err)
	}

	// Generate mock id token
	idToken, err := generateMockIDToken(nonce, "https://github.com/openpubkey", "me")
	if err != nil {
		t.Fatal(err)
	}

	// LUCIE: shouldn't we be verifying the id token before we use it to generate the cic headers?

	// Sign mock id token payload with cic headers
	cicToken, err := cic.Sign(signer, idToken)
	if err != nil {
		t.Fatal(err)
	}

	// Combine two tokens into a PK Token
	_, err = pktoken.New(idToken, cicToken)
	if err != nil {
		t.Fatal(err)
	}
}

func generateMockIDToken(nonce, issuer, audience string) ([]byte, error) {
	token := openid.New()

	token.Set(`nonce`, nonce)

	// Required token payload values for OpenID
	token.Set(jwt.IssuerKey, issuer)
	token.Set(jwt.AudienceKey, audience)
	token.Set(jwt.IssuedAtKey, time.Now().Unix())
	token.Set(jwt.ExpirationKey, time.Now().Add(24*time.Hour).Unix())
	token.Set(jwt.SubjectKey, "1234567890")

	signer, err := signer.NewRSASigner()
	if err != nil {
		return nil, err
	}

	// Sign the token with the secret key
	signedToken, err := jwt.Sign(token, jwt.WithKey(signer.JWKKey().Algorithm(), signer.SigningKey()))
	if err != nil {
		return nil, err
	}

	return signedToken, nil
}
