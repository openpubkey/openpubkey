package pktoken

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"

	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/util"
)

func (p *PKToken) Verify(ctx context.Context, commitmentClaim string) error {
	alg, ok := p.ProviderAlgorithm()
	if !ok {
		return fmt.Errorf("provider algorithm type missing")
	}

	var claims map[string]string
	if err := json.Unmarshal(p.Payload, &claims); err != nil {
		return err
	}
	issuer, ok := claims["iss"]
	if !ok {
		return fmt.Errorf("missing issuer claim in payload")
	}

	switch alg {
	case gq.GQ256:
		origHeaders, err := p.OriginalTokenHeaders()
		if err != nil {
			return fmt.Errorf("malformatted PK token headers: %w", err)
		}

		alg := origHeaders.Algorithm()
		if alg != jwa.RS256 {
			return fmt.Errorf("expected original headers to contain RS256 alg, got %s", alg)
		}

		pubKey, err := DiscoverPublicKey(ctx, origHeaders.KeyID(), issuer)
		if err != nil {
			return fmt.Errorf("failed to get OP public key: %w", err)
		}

		// GQ security parameter is always 256 for signature type GQ256
		err = p.VerifyGQSig(pubKey)
		if err != nil {
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

	err := p.VerifyCicSig()
	if err != nil {
		return fmt.Errorf("error verifying client signature on PK Token: %w", err)
	}

	if p.Cos != nil {
		if err := p.VerifyCosignerSignature(); err != nil {
			return fmt.Errorf("error verify cosigner signature on PK Token: %w", err)
		}
	}

	// Verify commitment is equal to hash of client instance claims (CIC)
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

func (p *PKToken) OriginalTokenHeaders() (jws.Headers, error) {
	opHeaders := p.Op.ProtectedHeaders()
	if opHeaders.Algorithm() != gq.GQ256 {
		return nil, fmt.Errorf("expected GQ256 alg, got %s", opHeaders.Algorithm())
	}

	// Original headers are stored as new headers' Key ID ("kid") field
	origHeadersB64 := []byte(opHeaders.KeyID())

	origHeaders, err := util.Base64DecodeForJWT(origHeadersB64)
	if err != nil {
		return nil, fmt.Errorf("error decoding original token headers: %w", err)
	}

	headers := jws.NewHeaders()
	err = json.Unmarshal(origHeaders, &headers)
	if err != nil {
		return nil, fmt.Errorf("error parsing segment: %w", err)
	}

	return headers, nil
}
