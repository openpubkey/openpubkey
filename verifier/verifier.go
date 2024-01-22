package verifier

import (
	"github.com/openpubkey/openpubkey/pktoken"
)

type Provider interface{}
type Cosigner interface{}

type Verifier struct{}

func New(providers []Provider, cosigners []Cosigner, options ...Option) (*Verifier, error) {
	return nil, nil
}

func VerifyPKToken(token *pktoken.PKToken) error {
	return nil
}
