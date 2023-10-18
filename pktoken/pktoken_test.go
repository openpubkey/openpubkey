package pktoken_test

import (
	"crypto"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/jwt/openid"
	"github.com/stretchr/testify/require"

	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/util"
)

func TestPkToken(t *testing.T) {
	alg := jwa.ES256

	signingKey, err := util.GenKeyPair(alg)
	if err != nil {
		t.Fatal(err)
	}

	jwkKey, err := jwk.PublicKeyOf(signingKey)
	if err != nil {
		t.Fatal(err)
	}
	jwkKey.Set(jwk.AlgorithmKey, alg)

	pkt, err := generateMockPKToken(signingKey, jwkKey)
	if err != nil {
		t.Fatal(err)
	}

	testPkTokenMessageSigning(t, pkt, signingKey)
	testPkTokenSerialization(t, pkt)
}

func testPkTokenMessageSigning(t *testing.T, pkt *pktoken.PKToken, signingKey crypto.Signer) {
	// Create new OpenPubKey Signed Message (OSM)
	msg := "test message!"
	osm, err := pkt.NewSignedMessage([]byte(msg), signingKey)
	if err != nil {
		t.Fatal(err)
	}

	// Verify our OSM is valid
	payload, err := pkt.VerifySignedMessage(osm)
	if err != nil {
		t.Fatal(err)
	}

	if string(payload) != msg {
		t.Fatal("OSM payload did not match what we initially wrapped")
	}
}

func testPkTokenSerialization(t *testing.T, pkt *pktoken.PKToken) {
	// Test json serialization/deserialization
	pktJson, err := pkt.ToJSON()
	if err != nil {
		t.Fatal(err)
	}

	token, err := pktoken.FromJSON(pktJson)
	if err != nil {
		t.Fatal(err)
	}

	tokenJson, err := token.ToJSON()
	if err != nil {
		t.Fatal(err)
	}

	require.JSONEq(t, string(pktJson), string(tokenJson))
}

func generateMockPKToken(signingKey crypto.Signer, jwkKey jwk.Key) (*pktoken.PKToken, error) {
	cic, err := clientinstance.NewClaims(jwkKey, map[string]any{})
	if err != nil {
		return nil, err
	}

	// Calculate our nonce from our cic values
	nonce, err := cic.Commitment()
	if err != nil {
		return nil, err
	}

	// Generate mock id token
	idToken, err := generateMockIDToken(nonce, "https://github.com/openpubkey", "me")
	if err != nil {
		return nil, err
	}

	// Sign mock id token payload with cic headers
	cicToken, err := cic.Sign(signingKey, jwkKey.Algorithm(), idToken)
	if err != nil {
		return nil, err
	}

	// Combine two tokens into a PK Token
	return pktoken.New(idToken, cicToken)
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

	alg := jwa.RS256
	signingKey, err := util.GenKeyPair(alg)
	if err != nil {
		return nil, err
	}

	// Sign the token with the secret key
	signedToken, err := jwt.Sign(token, jwt.WithKey(alg, signingKey))
	if err != nil {
		return nil, err
	}

	return signedToken, nil
}
