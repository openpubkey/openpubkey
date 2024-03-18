package discover

import (
	"context"
	"crypto"
	"encoding/json"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func MockGetJwksByIssuer(publicKey crypto.PublicKey, keyID string, alg string) (JwksFunc, error) {
	// Create JWKS (JWK Set)
	jwkKey, err := jwk.PublicKeyOf(publicKey)
	if err != nil {
		return nil, err
	}

	jwkKey.Set(jwk.AlgorithmKey, alg)
	jwkKey.Set(jwk.KeyIDKey, keyID)

	// Put our jwk into a set
	jwks := jwk.NewSet()
	jwks.AddKey(jwkKey)

	jwksJson, err := json.Marshal(jwks)
	if err != nil {
		return nil, err
	}

	return func(ctx context.Context, issuer string) ([]byte, error) {
		return jwksJson, nil
	}, nil
}
