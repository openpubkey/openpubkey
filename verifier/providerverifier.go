package verifier

type ProviderVerifier struct {
	issuer          string
	commitmentClaim string
	options         ProviderVerifierOpts
}

type ProviderVerifierOpts struct {
	// If ClientID is specified, then verification will require that the ClientID
	// be present in the audience ("aud") claim of the PK token payload
	ClientID string
}

func NewProviderVerifier(issuer, commitmentClaim string, options ProviderVerifierOpts) *ProviderVerifier {
	return &ProviderVerifier{
		issuer:          issuer,
		commitmentClaim: commitmentClaim,
		options:         options,
	}
}
