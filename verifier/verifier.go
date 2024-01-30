package verifier

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/openpubkey/openpubkey/pktoken"
)

type VerifierOption func(*pktoken.PKToken) error

// Verifies whether a PK token is valid and matches all expected claims.
//
// issuer: Is the OpenID provider issuer as seen in ID token e.g. "https://accounts.google.com"
// commitmentClaim: the ID token payload claim name where the cicHash was stored during issuance
func VerifyPKToken(
	ctx context.Context,
	issuer string,
	commitmentClaim string,
	pkt *pktoken.PKToken,
	options ...VerifierOption,
) error {
	// Have our pk token verify itself including checking whether the hash of the client instance claims (CIC) is
	// equal to some claim in the payload
	if err := pkt.Verify(context.Background(), commitmentClaim); err != nil {
		return err
	}

	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		return err
	}

	// Check that our provider issuer matches expected
	if issuer != claims.Issuer {
		return fmt.Errorf("unexpected issuer: %s, expected %s", claims.Issuer, issuer)
	}

	// Enforce all additional, optional checks
	for _, option := range options {
		// cycles through any provided options, returning the first error if any
		if err := option(pkt); err != nil {
			return err
		}
	}

	return nil
}
