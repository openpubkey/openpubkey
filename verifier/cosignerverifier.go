package verifier

import (
	"context"
	"crypto"
	"fmt"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/pktoken"
	oidcclient "github.com/zitadel/oidc/v2/pkg/client"
)

type DefaultCosignerVerifier struct {
	issuer  string
	options CosignerVerifierOpts
}

type CosignerVerifierOpts struct {
	// Strict specifies whether or not a pk token MUST contain a signature by this cosigner.
	// Defaults to true.
	Strict *bool
	// Allows users to set custom function for discovering public key of Cosigner
	DiscoverPublicKey func(ctx context.Context, kid string, issuer string) (crypto.PublicKey, error)
}

func NewCosignerVerifier(issuer string, options CosignerVerifierOpts) *DefaultCosignerVerifier {
	v := &DefaultCosignerVerifier{
		issuer:  issuer,
		options: options,
	}

	// If no custom DiscoverPublicKey function is set, set default
	if v.options.DiscoverPublicKey == nil {
		v.options.DiscoverPublicKey = discoverCosignerPublicKey
	}

	// If strict is not set, then default it to true
	if v.options.Strict == nil {
		v.options.Strict = new(bool)
		*v.options.Strict = true
	}

	return v
}

func (v *DefaultCosignerVerifier) Issuer() string {
	return v.issuer
}

func (v *DefaultCosignerVerifier) Strict() bool {
	return *v.options.Strict
}

func (v *DefaultCosignerVerifier) VerifyCosigner(ctx context.Context, pkt *pktoken.PKToken) error {
	if pkt.Cos == nil {
		return fmt.Errorf("no cosigner signature")
	}

	// Parse our header
	header, err := pkt.ParseCosignerClaims()
	if err != nil {
		return err
	}

	key, err := v.options.DiscoverPublicKey(ctx, header.KeyID, header.Issuer)
	if err != nil {
		return err
	}

	// Check if it's expired
	if time.Now().After(time.Unix(header.Expiration, 0)) {
		return fmt.Errorf("cosigner signature expired")
	}

	_, err = jws.Verify(pkt.CosToken, jws.WithKey(jwa.KeyAlgorithmFrom(jwa.RS256), key))

	return err
}

func discoverCosignerPublicKey(ctx context.Context, kid string, issuer string) (crypto.PublicKey, error) {
	discConf, err := oidcclient.Discover(issuer, http.DefaultClient)
	if err != nil {
		return nil, fmt.Errorf("failed to call OIDC discovery endpoint: %w", err)
	}
	set, err := jwk.Fetch(context.Background(), discConf.JwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public keys from Cosigner JWKS endpoint: %w", err)
	}

	key, ok := set.LookupKeyID(kid)
	if !ok {
		return nil, fmt.Errorf("missing key id (kid)")
	}

	return key, nil
}
