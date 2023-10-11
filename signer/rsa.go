package signer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// This functions as a wrapper around ecdsa, it's main function is to strictly
// tie together the signing key, public key, and algorithm
type rsaSigner struct {
	signingKey *rsa.PrivateKey
	jwkKey     jwk.Key
}

func NewRSASigner() (*rsaSigner, error) {
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %s", err)
	}

	jwkKey, err := jwk.PublicKeyOf(signingKey)
	if err != nil {
		return nil, err
	}

	alg := jwa.KeyAlgorithmFrom("RS256") // RSASSA-PKCS-v1.5 using SHA-256
	jwkKey.Set(jwk.AlgorithmKey, alg)

	return &rsaSigner{
		signingKey: signingKey,
		jwkKey:     jwkKey,
	}, nil
}

func (s *rsaSigner) Sign(message []byte) ([]byte, error) {
	digest, err := hash(message)
	if err != nil {
		return nil, err
	}

	// sign the hashed message
	return s.signingKey.Sign(rand.Reader, digest, crypto.SHA256)
}

func (s *rsaSigner) SigningKey() any {
	return s.signingKey
}

func (s *rsaSigner) PublicKey() any {
	return s.signingKey.Public()
}

func (s *rsaSigner) JWKKey() jwk.Key {
	return s.jwkKey
}
