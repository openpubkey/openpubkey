package verifier

import (
	"context"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type ProviderVerifier struct {
	issuer          string
	commitmentClaim string
	options         ProviderVerifierOpts
}

type ProviderVerifierOpts struct {
	// If ClientID is specified, then verification will require that the ClientID
	// be present in the audience ("aud") claim of the PK token payload
	ClientID string
	// Allows users to set custom function for discovering public key of Provider
	DiscoverPublicKey func(ctx context.Context, kid string, issuer string) (jwk.Key, error)
}

// Creates a new ProviderVerifier with required fields
//
// issuer: Is the OpenID provider issuer as seen in ID token e.g. "https://accounts.google.com"
// commitmentClaim: the ID token payload claim name where the cicHash was stored during issuance
func NewProviderVerifier(issuer, commitmentClaim string, options ProviderVerifierOpts) *ProviderVerifier {
	return &ProviderVerifier{
		issuer:          issuer,
		commitmentClaim: commitmentClaim,
		options:         options,
	}
}
