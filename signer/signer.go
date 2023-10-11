package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type Signer struct {
	signingKey crypto.Signer
	jwkKey     jwk.Key
}

func NewECDSASigner() (*Signer, error) {
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %s", err)
	}

	jwkKey, err := jwk.PublicKeyOf(signingKey)
	if err != nil {
		return nil, err
	}
	jwkKey.Set(jwk.AlgorithmKey, jwa.ES256)

	return &Signer{
		signingKey: signingKey,
		jwkKey:     jwkKey,
	}, nil
}

func NewRSASigner() (*Signer, error) {
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

	return &Signer{
		signingKey: signingKey,
		jwkKey:     jwkKey,
	}, nil
}

func (s *Signer) Sign(message []byte) ([]byte, error) {
	digest, err := hash(message)
	if err != nil {
		return nil, err
	}

	// sign the hashed message
	return s.signingKey.Sign(rand.Reader, digest, crypto.SHA256)
}

func (s *Signer) SigningKey() crypto.Signer {
	return s.signingKey
}

func (s *Signer) JWKKey() jwk.Key {
	return s.jwkKey
}

func hash(message []byte) ([]byte, error) {
	// hash the message
	msgHash := sha256.New()
	_, err := msgHash.Write(message)
	if err != nil {
		return nil, err
	}
	msgHashSum := msgHash.Sum(nil)

	return msgHashSum, nil
}
