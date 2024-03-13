package providers

import (
	"context"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/gq"
)

func CreateGQToken(ctx context.Context, idToken []byte, op OpenIdProvider) ([]byte, error) {
	headersB64, _, _, err := jws.SplitCompact(idToken)
	if err != nil {
		return nil, fmt.Errorf("error getting original headers: %w", err)
	}

	headers := jws.NewHeaders()
	err = parseJWTSegment(headersB64, &headers)
	if err != nil {
		return nil, err
	}

	opKey, err := op.PublicKey(ctx, headers)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := opKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("gq signatures require original provider to have signed with an RSA key")
	}

	sv, err := gq.New256SignerVerifier(rsaKey)
	if err != nil {
		return nil, fmt.Errorf("error creating GQ signer: %w", err)
	}
	gqToken, err := sv.SignJWT(idToken)
	if err != nil {
		return nil, fmt.Errorf("error creating GQ signature: %w", err)
	}

	return gqToken, nil
}
