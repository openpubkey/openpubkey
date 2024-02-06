package verifier

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/openpubkey/openpubkey/pktoken"
)

type Verifier interface {
	AddCosignerVerifier(issuer string, strict bool)
	VerifyPKToken(ctx context.Context, pkt *pktoken.PKToken, checks ...Check) error
}

type Check func(*pktoken.PKToken) error

type cosignerOpts struct {
	issuer string
	strict bool
}

type verifier struct {
	issuer           string
	commitmentClaim  string
	cosignerVerifier cosignerOpts
}

func New(issuer, commitmentClaim string) Verifier {
	return &verifier{
		issuer:          issuer,
		commitmentClaim: commitmentClaim,
	}
}

func (v *verifier) AddCosignerVerifier(issuer string, strict bool) {
	v.cosignerVerifier = cosignerOpts{
		issuer: issuer,
		strict: strict,
	}
}

// Verifies whether a PK token is valid and matches all expected claims.
//
// issuer: Is the OpenID provider issuer as seen in ID token e.g. "https://accounts.google.com"
// commitmentClaim: the ID token payload claim name where the cicHash was stored during issuance
// checks: Allows specification of additional checks
func (v *verifier) VerifyPKToken(
	ctx context.Context,
	pkt *pktoken.PKToken,
	extraChecks ...Check,
) error {
	// Have our pk token verify itself including checking whether the hash of the client instance claims (CIC) is
	// equal to some claim in the payload
	if err := pkt.Verify(context.Background(), v.commitmentClaim); err != nil {
		return err
	}

	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		return err
	}

	// Check that our provider issuer matches expected
	if v.issuer != claims.Issuer {
		return fmt.Errorf("unexpected issuer: %s, expected %s", claims.Issuer, v.issuer)
	}

	if v.cosignerVerifier.issuer != "" {
		if pkt.Cos == nil {
			if v.cosignerVerifier.strict {
				return fmt.Errorf("missing required cosigner")
			}
		} else {
			claims, err := pkt.ParseCosignerClaims()
			if err != nil {
				return err
			}

			if claims.Issuer != v.issuer {
				return fmt.Errorf("expected cosigner: %s, expected %s", claims.Issuer, v.issuer)
			}
		}
	}

	// Enforce all additional, optional checks
	for _, option := range extraChecks {
		// cycles through any provided options, returning the first error if any
		if err := option(pkt); err != nil {
			return err
		}
	}

	return nil
}
