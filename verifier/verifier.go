package verifier

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/openpubkey/openpubkey/pktoken"
)

type Verifier struct {
	providers map[string]*ProviderVerifier
	cosigners map[string]*CosignerVerifier
}

func New(verifier *ProviderVerifier, options ...VerifierOpts) *Verifier {
	v := &Verifier{
		providers: map[string]*ProviderVerifier{
			verifier.issuer: verifier,
		},
		cosigners: map[string]*CosignerVerifier{},
	}

	for _, option := range options {
		option(v)
	}

	return v
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
	// If our issuer does not match any providers, throw an error
	if !ok {
		return fmt.Errorf("unrecognized issuer: %s", issuer)
	}

	// Have our pk token verify itself including checking whether the hash of the client instance claims (CIC) is
	// equal to some claim in the payload
	if err := pkt.Verify(context.Background(), providerVerfier.commitmentClaim); err != nil {
		return err
	}

	// If ClientID is specified, verify clientID is contained in the audience
	if providerVerfier.options.ClientID != "" {
		if err := verifyAudience(pkt, providerVerfier.options.ClientID); err != nil {
			return err
		}
	}

	if len(v.cosigners) > 0 {
		if pkt.Cos == nil {
			// If there's no cosigner signature and any provided cosigner verifiers are strict, then return error
			for _, cosignerVerifier := range v.cosigners {
				if cosignerVerifier.options.Strict {
					return fmt.Errorf("missing required cosigner signature by %s", cosignerVerifier.issuer)
				}
			}
		} else {
			cosignerClaims, err := pkt.ParseCosignerClaims()
			if err != nil {
				return err
			}

			_, ok := v.cosigners[cosignerClaims.Issuer]
			if !ok {
				// If other cosigners are present, do we accept?
				return fmt.Errorf("unrecognized cosigner %s", cosignerClaims.Issuer)
			}

			// If any other cosigner verifiers are set to strict but aren't present, then return error
			for _, cosignerVerifier := range v.cosigners {
				if cosignerVerifier.options.Strict && cosignerVerifier.issuer != cosignerClaims.Issuer {
					return fmt.Errorf("missing required cosigner signature by %s", cosignerVerifier.issuer)
				}
			}
		}
	}

	// Cycles through any provided additional checks and returns the first error, if any.
	for _, check := range extraChecks {
		if err := check(v, pkt); err != nil {
			return err
		}
	}

	return nil
}

func verifyAudience(pkt *pktoken.PKToken, clientID string) error {
	var claims struct {
		Audience any `json:"aud"`
	}
	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		return err
	}

	switch aud := claims.Audience.(type) {
	case string:
		if aud != clientID {
			return fmt.Errorf("audience does not contain clientID %s, aud = %s", clientID, aud)
		}
	case []string:
		for _, audience := range aud {
			if audience == clientID {
				return nil
			}
		}
		return fmt.Errorf("audience does not contain clientID %s, aud = %v", clientID, aud)
	default:
		return fmt.Errorf("missing audience claim")
	}
	return nil
}
