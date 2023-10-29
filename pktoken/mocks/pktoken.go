package mocks

import (
	"crypto"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/openpubkey/openpubkey/parties"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
)

func GenerateMockPKToken(signingKey crypto.Signer, alg jwa.KeyAlgorithm) (*pktoken.PKToken, error) {
	jwkKey, err := jwk.PublicKeyOf(signingKey)
	if err != nil {
		return nil, err
	}
	jwkKey.Set(jwk.AlgorithmKey, alg)

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
	op, err := parties.NewMockOpenIdProvider()
	if err != nil {
		return nil, err
	}

	idToken, err := op.RequestTokens(string(nonce))
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
