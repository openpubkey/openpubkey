package verifier

type CosignerVerifier struct {
	issuer  string
	options CosignerVerifierOpts
}

type CosignerVerifierOpts struct {
	// Strict specifies whether or not a pk token MUST contain a signature by this cosigner.
	// Defaults to false.
	Strict bool
}

func NewCosignerVerifier(issuer string, options CosignerVerifierOpts) *CosignerVerifier {
	return &CosignerVerifier{
		issuer:  issuer,
		options: options,
	}
}
