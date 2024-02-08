package mocks

import (
	"context"
	"crypto"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/openpubkey/openpubkey/client/mocks"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
)

func GenerateMockPKToken(t *testing.T, signingKey crypto.Signer, alg jwa.KeyAlgorithm) (*pktoken.PKToken, error) {
	return GenerateMockPKTokenWithEmail(t, signingKey, alg, "")
}

func GenerateMockPKTokenWithEmail(t *testing.T, signingKey crypto.Signer, alg jwa.KeyAlgorithm, email string) (*pktoken.PKToken, error) {

	jwkKey, err := jwk.PublicKeyOf(signingKey)
	if err != nil {
		return nil, err
	}
	err = jwkKey.Set(jwk.AlgorithmKey, alg)
	if err != nil {
		return nil, err
	}

	if email != "" {
		err = jwkKey.Set("email", email)
		if err != nil {
			return nil, err
		}
	}

	cic, err := clientinstance.NewClaims(jwkKey, map[string]any{})
	if err != nil {
		return nil, err
	}

	// Calculate our nonce from our cic values
	nonce, err := cic.Hash()
	if err != nil {
		return nil, err
	}

	// Generate mock id token
	op, err := mocks.NewMockOpenIdProvider(t, map[string]any{})
	if err != nil {
		return nil, err
	}

	idToken, err := op.RequestTokens(context.Background(), string(nonce))
	if err != nil {
		return nil, err
	}

	// Sign mock id token payload with cic headers
	cicToken, err := cic.Sign(signingKey, jwkKey.Algorithm(), idToken.Bytes())
	if err != nil {
		return nil, err
	}

	// Combine two tokens into a PK Token
	return pktoken.New(idToken.Bytes(), cicToken)
}
