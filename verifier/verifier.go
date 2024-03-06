package verifier

import (
	"context"
	"crypto"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/pktoken"
)

type ProviderVerifier interface {
	// Returns the OpenID provider issuer as seen in ID token e.g. "https://accounts.google.com"
	Issuer() string
	ProviderPublicKey(ctx context.Context, token []byte) (crypto.PublicKey, error)
	VerifyProvider(ctx context.Context, pkt *pktoken.PKToken) error
}

type CosignerVerifier interface {
	Issuer() string
	Strict() bool // Whether or not a given cosigner MUST be present for successful verification
	VerifyCosigner(ctx context.Context, pkt *pktoken.PKToken) error
}

type VerifierOpts func(*Verifier) error

func WithCosignerVerifiers(verifiers ...*DefaultCosignerVerifier) VerifierOpts {
	return func(v *Verifier) error {
		for _, verifier := range verifiers {
			if _, ok := v.cosigners[verifier.Issuer()]; ok {
				return fmt.Errorf("cosigner verifier found with duplicate issuer: %s", verifier.Issuer())
			}
			v.cosigners[verifier.issuer] = verifier
		}
		return nil
	}
}

func AddProviderVerifiers(verifiers ...ProviderVerifier) VerifierOpts {
	return func(v *Verifier) error {
		for _, verifier := range verifiers {
			if _, ok := v.providers[verifier.Issuer()]; ok {
				return fmt.Errorf("provider verifier found with duplicate issuer: %s", verifier.Issuer())
			}
			v.providers[verifier.Issuer()] = verifier
		}
		return nil
	}
}

type Verifier struct {
	providers map[string]ProviderVerifier
	cosigners map[string]CosignerVerifier
}

func New(verifier ProviderVerifier, options ...VerifierOpts) (*Verifier, error) {
	v := &Verifier{
		providers: map[string]ProviderVerifier{
			verifier.Issuer(): verifier,
		},
		cosigners: map[string]CosignerVerifier{},
	}

	for _, option := range options {
		if err := option(v); err != nil {
			return nil, err
		}
	}

	return v, nil
}

// Verifies whether a PK token is valid and matches all expected claims.
//
// extraChecks: Allows for optional specification of additional checks
func (v *Verifier) VerifyPKToken(
	ctx context.Context,
	pkt *pktoken.PKToken,
	extraChecks ...Check,
) error {
	issuer, err := pkt.Issuer()
	if err != nil {
		return err
	}

	providerVerfier, ok := v.providers[issuer]
	if !ok {
		return fmt.Errorf("unrecognized issuer: %s", issuer)
	}

	if err := providerVerfier.VerifyProvider(ctx, pkt); err != nil {
		return err
	}

	if len(v.cosigners) > 0 {
		if pkt.Cos == nil {
			// If there's no cosigner signature and any provided cosigner verifiers are strict, then return error
			for _, cosignerVerifier := range v.cosigners {
				if cosignerVerifier.Strict() {
					return fmt.Errorf("missing required cosigner signature by %s", cosignerVerifier.Issuer())
				}
			}
		} else {
			cosignerClaims, err := pkt.ParseCosignerClaims()
			if err != nil {
				return err
			}

			cosignerVerifier, ok := v.cosigners[cosignerClaims.Issuer]
			if !ok {
				// If other cosigners are present, do we accept?
				return fmt.Errorf("unrecognized cosigner %s", cosignerClaims.Issuer)
			}

			// Verify cosigner signature
			if err := cosignerVerifier.VerifyCosigner(ctx, pkt); err != nil {
				return err
			}

			// If any other cosigner verifiers are set to strict but aren't present, then return error
			for _, cosignerVerifier := range v.cosigners {
				if cosignerVerifier.Strict() && cosignerVerifier.Issuer() != cosignerClaims.Issuer {
					return fmt.Errorf("missing required cosigner signature by %s", cosignerVerifier.Issuer())
				}
			}
		}
	}

	if err := VerifyCicSignature(pkt); err != nil {
		return fmt.Errorf("error verifying client signature on PK Token: %w", err)
	}

	// Cycles through any provided additional checks and returns the first error, if any.
	for _, check := range extraChecks {
		if err := check(v, pkt); err != nil {
			return err
		}
	}

	return nil
}

func VerifyCicSignature(pkt *pktoken.PKToken) error {
	token, err := pkt.Compact(pkt.Cic)
	if err != nil {
		return err
	}

	cic, err := pkt.GetCicValues()
	if err != nil {
		return err
	}

	_, err = jws.Verify(token, jws.WithKey(cic.PublicKey().Algorithm(), cic.PublicKey()))
	return err
}
