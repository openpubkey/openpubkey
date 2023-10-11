package signer

import (
	"crypto/sha256"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type Signer interface {
	Sign(message []byte) ([]byte, error)
	SigningKey() any
	PublicKey() any
	JWKKey() jwk.Key
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
