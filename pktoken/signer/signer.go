package signer

import (
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type Signer interface {
	Sign(message []byte) ([]byte, error)
	SecretKey() any
	PublicKey() jwk.Key
	KeyAlgorithm() jwa.KeyAlgorithm
}
