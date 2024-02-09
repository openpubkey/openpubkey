package verifier

import (
	"context"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type CosignerVerifier struct {
	issuer  string
	options CosignerVerifierOpts
}

type CosignerVerifierOpts struct {
	// Strict specifies whether or not a pk token MUST contain a signature by this cosigner.
	// Defaults to false.
	Strict bool
	// Allows users to set custom function for discovering public key of Cosigner
	DiscoverPublicKey func(ctx context.Context, kid string, issuer string) (jwk.Key, error)
}

func NewCosignerVerifier(issuer string, options CosignerVerifierOpts) *CosignerVerifier {
	return &CosignerVerifier{
		issuer:  issuer,
		options: options,
	}
}
