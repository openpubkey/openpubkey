package verifier

import "fmt"

type VerifierOpts func(*Verifier)

func WithCosignerVerifiers(verifiers ...*DefaultCosignerVerifier) VerifierOpts {
	return func(v *Verifier) {
		for _, verifier := range verifiers {
			fmt.Println(verifier.issuer)
			v.cosigners[verifier.issuer] = verifier
		}
	}
}

func AddProviderVerifiers(verifiers ...ProviderVerifier) VerifierOpts {
	return func(v *Verifier) {
		for _, verifier := range verifiers {
			v.providers[verifier.Issuer()] = verifier
		}
	}
}
