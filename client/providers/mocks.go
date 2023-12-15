package providers

import (
	"context"
	"crypto"
	"time"

	"github.com/awnumar/memguard"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/jwt/openid"
	"github.com/openpubkey/openpubkey/util"
)

const (
	MockIssuer   = "me"
	MockAudience = "also_me"
)

type MockOpenIdProvider struct {
	alg    jwa.KeyAlgorithm
	signer crypto.Signer
}

func NewMockOpenIdProvider() (*MockOpenIdProvider, error) {
	alg := jwa.RS256
	signingKey, err := util.GenKeyPair(alg)
	if err != nil {
		return nil, err
	}

	return &MockOpenIdProvider{
		alg:    alg,
		signer: signingKey,
	}, nil
}

func (m *MockOpenIdProvider) RequestTokens(ctx context.Context, cicHash string) (*memguard.LockedBuffer, error) {
	token := openid.New()

	token.Set("nonce", cicHash)
	token.Set("email", "arthur.aardvark@example.com")

	// Required token payload values for OpenID
	token.Set(jwt.IssuerKey, MockIssuer)
	token.Set(jwt.AudienceKey, MockAudience)
	token.Set(jwt.IssuedAtKey, time.Now().Unix())
	token.Set(jwt.ExpirationKey, time.Now().Add(24*time.Hour).Unix())
	token.Set(jwt.SubjectKey, "1234567890")

	// Sign the token with the secret key
	signedToken, err := jwt.Sign(token, jwt.WithKey(m.alg, m.signer))
	if err != nil {
		return nil, err
	}
	return memguard.NewBufferFromBytes(signedToken), nil
}

func (m *MockOpenIdProvider) Issuer() string {
	return MockIssuer
}

func (m *MockOpenIdProvider) PublicKey(ctx context.Context, headers jws.Headers) (crypto.PublicKey, error) {
	return m.signer.Public(), nil
}

func (m *MockOpenIdProvider) VerifyCICHash(ctx context.Context, idt []byte, expectedCICHash string) error {
	return nil
}

func (m *MockOpenIdProvider) VerifyNonGQSig(ctx context.Context, idt []byte, expectedNonce string) error {
	return nil
}
