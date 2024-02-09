package pktoken

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"

	"github.com/openpubkey/openpubkey/gq"
)

func (p *PKToken) Verify(ctx context.Context, commitmentClaim string) error {
	alg, ok := p.ProviderAlgorithm()
	if !ok {
		return fmt.Errorf("provider algorithm type missing")
	}

	switch alg {
	case gq.GQ256:
		if err := p.VerifyGQSig(ctx); err != nil {
			return fmt.Errorf("error verifying OP GQ signature on PK Token: %w", err)
		}
	case jwa.RS256:
		pubKey, err := p.ProviderPublicKey(ctx)
		if err != nil {
			return fmt.Errorf("failed to get OP public key: %w", err)
		}

		token, err := p.Compact(p.Op)
		if err != nil {
			return err
		}

		if _, err := jws.Verify(token, jws.WithKey(alg, pubKey)); err != nil {
			return err
		}
	}

	if err := p.VerifyCicSig(); err != nil {
		return fmt.Errorf("error verifying client signature on PK Token: %w", err)
	}

	if p.Cos != nil {
		if err := p.VerifyCosignerSignature(); err != nil {
			return fmt.Errorf("error verify cosigner signature on PK Token: %w", err)
		}
	}

	return p.VerifyCommitment(commitmentClaim)
}

// Verifies commitment in header is equal to hash of client instance claims (CIC)
// commitmentClaim: the token payload claim name where the CIC hash was stored during issuance e.g. "nonce" or "aud"
func (p *PKToken) VerifyCommitment(commitmentClaim string) error {
	var claims map[string]string
	if err := json.Unmarshal(p.Payload, &claims); err != nil {
		return err
	}

	cic, err := p.GetCicValues()
	if err != nil {
		return err
	}
	expectedCommitment, err := cic.Hash()
	if err != nil {
		return err
	}
	commitment, ok := claims[commitmentClaim]
	if !ok {
		return fmt.Errorf("missing commitment claim %s", commitmentClaim)
	}

	if commitment != string(expectedCommitment) {
		return fmt.Errorf("nonce claim doesn't match, got %q, expected %q", commitment, string(expectedCommitment))
	}
	return nil
}
