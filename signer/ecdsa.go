package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// This functions as a wrapper around ecdsa, it's main function is to strictly
// tie together the signing key, public key, and algorithm
type ecdsaSigner struct {
	signingKey *ecdsa.PrivateKey
	jwkKey     jwk.Key
}

func NewECDSASigner() (*ecdsaSigner, error) {
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %s", err)
	}

	jwkKey, err := jwk.PublicKeyOf(signingKey)
	if err != nil {
		return nil, err
	}
	jwkKey.Set(jwk.AlgorithmKey, jwa.ES256)

	return &ecdsaSigner{
		signingKey: signingKey,
		jwkKey:     jwkKey,
	}, nil
}

func (s *ecdsaSigner) Sign(message []byte) ([]byte, error) {
	digest, err := hash(message)
	if err != nil {
		return nil, err
	}

	// sign the hashed message
	return s.signingKey.Sign(rand.Reader, digest, crypto.SHA256)
}

func (s *ecdsaSigner) SigningKey() any {
	return s.signingKey
}

func (s *ecdsaSigner) PublicKey() any {
	return s.signingKey.Public()
}

func (s *ecdsaSigner) JWKKey() jwk.Key {
	return s.jwkKey
}
