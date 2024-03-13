package discover

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/util"

	oidcclient "github.com/zitadel/oidc/v2/pkg/client"
)

func ProviderPublicKey(ctx context.Context, headers jws.Headers, issuer string) (crypto.PublicKey, error) {
	// If GQ then pull the kid from the original headers
	if headers.Algorithm() == gq.GQ256 {
		origHeadersB64 := []byte(headers.KeyID())
		origHeadersJson, err := util.Base64DecodeForJWT(origHeadersB64)
		if err != nil {
			return nil, fmt.Errorf("error base64 decoding GQ kid: %w", err)
		}

		err = json.Unmarshal(origHeadersJson, &headers)
		if err != nil {
			return nil, fmt.Errorf("error unmarshalling GQ kid to original headers: %w", err)
		}
	}

	discConf, err := oidcclient.Discover(issuer, http.DefaultClient)
	if err != nil {
		return nil, fmt.Errorf("failed to call OIDC discovery endpoint: %w", err)
	}
	jwks, err := jwk.Fetch(ctx, discConf.JwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch to JWKS: %w", err)
	}

	kid := headers.KeyID()
	key, ok := jwks.LookupKeyID(kid)
	if !ok {
		return nil, fmt.Errorf("key %s isn't in JWKS", kid)
	}

	if key.Algorithm() != jwa.RS256 {
		return nil, fmt.Errorf("expected alg to be RS256 in JWK with kid %q for OP %q, got %q", kid, issuer, key.Algorithm())
	}

	pubKey := new(rsa.PublicKey)
	err = key.Raw(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	return pubKey, err
}
