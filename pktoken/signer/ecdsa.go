package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type EcdsaSigner struct {
	privateKey   *ecdsa.PrivateKey
	publicKey    jwk.Key
	keyAlgorithm jwa.KeyAlgorithm
}

func NewEcdsaSigner() (signer *EcdsaSigner, err error) {
	signer.keyAlgorithm = jwa.ES256

	signer.privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %s", err)
	}

	if signer.publicKey, err = jwk.PublicKeyOf(signer.privateKey); err != nil {
		return nil, err
	}

	return
}

func (s *EcdsaSigner) Sign(message []byte) ([]byte, error) {
	// hash the message
	msgHash := sha256.New()
	_, err := msgHash.Write(message)
	if err != nil {
		return nil, err
	}
	msgHashSum := msgHash.Sum(nil)

	// sign the hashed message
	return s.privateKey.Sign(rand.Reader, msgHashSum, crypto.SHA256)
}

func (s *EcdsaSigner) SecretKey() any {
	return s.privateKey
}

func (s *EcdsaSigner) PublicKey() jwk.Key {
	return s.publicKey
}

func (s *EcdsaSigner) KeyAlgorithm() jwa.KeyAlgorithm {
	return s.keyAlgorithm
}
