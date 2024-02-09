package pktoken

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/util"
)

func (p *PKToken) VerifyGQSig(ctx context.Context) error {
	alg, ok := p.ProviderAlgorithm()
	if !ok {
		return fmt.Errorf("missing provider algorithm header")
	}

	if alg != gq.GQ256 {
		return fmt.Errorf("signature is not of type GQ")
	}

	origHeaders, err := p.originalTokenHeaders()
	if err != nil {
		return fmt.Errorf("malformatted PK token headers: %w", err)
	}

	alg = origHeaders.Algorithm()
	if alg != jwa.RS256 {
		return fmt.Errorf("expected original headers to contain RS256 alg, got %s", alg)
	}

	issuer, err := p.Issuer()
	if err != nil {
		return fmt.Errorf("missing issuer")
	}

	jwkKey, err := DiscoverPublicKey(ctx, origHeaders.KeyID(), issuer)
	if err != nil {
		return fmt.Errorf("failed to get OP public key: %w", err)
	}

	if jwkKey.Algorithm() != jwa.RS256 {
		return fmt.Errorf("expected alg to be RS256 in JWK with kid %q for OP %q, got %q", origHeaders.KeyID(), issuer, jwkKey.Algorithm())
	}

	pubKey := new(rsa.PublicKey)
	err = jwkKey.Raw(pubKey)
	if err != nil {
		return fmt.Errorf("failed to decode public key: %w", err)
	}

	token, err := p.Compact(p.Op)
	if err != nil {
		return err
	}

	sv, err := gq.New256SignerVerifier(pubKey)
	if err != nil {
		return err
	}
	ok = sv.VerifyJWT(token)
	if !ok {
		return fmt.Errorf("error verifying OP GQ signature on PK Token (ID Token invalid)")
	}
	return nil
}

func (p *PKToken) originalTokenHeaders() (jws.Headers, error) {
	opHeaders := p.Op.ProtectedHeaders()
	if opHeaders.Algorithm() != gq.GQ256 {
		return nil, fmt.Errorf("expected GQ256 alg, got %s", opHeaders.Algorithm())
	}

	opToken, err := p.Compact(p.Op)
	if err != nil {
		return nil, err
	}

	origHeadersB64, err := gq.OriginalJWTHeaders(opToken)
	if err != nil {
		return nil, fmt.Errorf("malformatted PK token headers: %w", err)
	}

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
