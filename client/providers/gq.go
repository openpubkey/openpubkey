package providers

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/util"
)

func CreateGQToken(ctx context.Context, idToken []byte, op OpenIdProvider) ([]byte, error) {
	headersB64, _, _, err := jws.SplitCompact(idToken)
	if err != nil {
		return nil, fmt.Errorf("error getting original headers: %w", err)
	}

	// TODO: We should create a util function for extracting headers from tokens
	headersJson, err := util.Base64DecodeForJWT(headersB64)
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding GQ kid: %w", err)
	}
	headers := jws.NewHeaders()
	err = json.Unmarshal(headersJson, &headers)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling GQ kid to original headers: %w", err)
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
