package verifier

import (
	"context"

	"github.com/openpubkey/openpubkey/pktoken"
)

type ProviderVerifier interface {
	Issuer() string
	// Returns the payload claim name where the cicHash was stored from RequestTokens
	CommitmentClaim() string
}
type CosignerVerifier interface{}

type Verifier struct {
	provider ProviderVerifier
}

func New(provider ProviderVerifier, cosigners []CosignerVerifier) (*Verifier, error) {
	return nil, nil
}

func (v *Verifier) VerifyPKToken(token *pktoken.PKToken, options ...Option) error {
	if err := token.Verify(context.Background(), v.provider.CommitmentClaim()); err != nil {
		return err
	}
	return nil
}
