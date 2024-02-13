package verifier

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
	oidcclient "github.com/zitadel/oidc/v2/pkg/client"
)

type ProviderVerifier struct {
	issuer          string
	commitmentClaim string
	options         ProviderVerifierOpts
}

type ProviderVerifierOpts struct {
	// If ClientID is specified, then verification will require that the ClientID
	// be present in the audience ("aud") claim of the PK token payload
	ClientID string
	// Custom function for discovering public key of Provider
	DiscoverPublicKey func(ctx context.Context, kid string, issuer string) (jwk.Key, error)
	// Allows for successful verification of expired tokens
	SkipExpirationCheck bool
}

// Creates a new ProviderVerifier with required fields
//
// issuer: Is the OpenID provider issuer as seen in ID token e.g. "https://accounts.google.com"
// commitmentClaim: the ID token payload claim name where the cicHash was stored during issuance
func NewProviderVerifier(issuer, commitmentClaim string, options ProviderVerifierOpts) *ProviderVerifier {
	v := &ProviderVerifier{
		issuer:          issuer,
		commitmentClaim: commitmentClaim,
		options:         options,
	}

	// If no custom DiscoverPublicKey function is set, set default
	if v.options.DiscoverPublicKey == nil {
		v.options.DiscoverPublicKey = DiscoverProviderPublicKey
	}

	return v
}

func (v *ProviderVerifier) VerifyProvider(ctx context.Context, pkt *pktoken.PKToken) error {
	// If ClientID is specified, verify clientID is contained in the audience
	if v.options.ClientID != "" {
		if err := verifyAudience(pkt, v.options.ClientID); err != nil {
			return err
		}
	}

	alg, ok := pkt.ProviderAlgorithm()
	if !ok {
		return fmt.Errorf("provider algorithm type missing")
	}

	switch alg {
	case gq.GQ256:
		if err := VerifyGQSig(ctx, pkt); err != nil {
			return fmt.Errorf("error verifying OP GQ signature on PK Token: %w", err)
		}
	case jwa.RS256:
		pubKey, err := v.ProviderPublicKey(ctx, pkt)
		if err != nil {
			return fmt.Errorf("failed to get OP public key: %w", err)
		}

		token, err := pkt.Compact(pkt.Op)
		if err != nil {
			return err
		}

		if _, err := jws.Verify(token, jws.WithKey(alg, pubKey)); err != nil {
			return err
		}
	}

	if err := v.verifyCommitment(pkt); err != nil {
		return err
	}

	return nil
}

func (v *ProviderVerifier) ProviderPublicKey(ctx context.Context, pkt *pktoken.PKToken) (jwk.Key, error) {
	alg, ok := pkt.ProviderAlgorithm()
	if !ok {
		return nil, fmt.Errorf("provider algorithm type missing")
	}

	var kid string
	if alg == gq.GQ256 {
		origHeaders, err := originalTokenHeaders(pkt)
		if err != nil {
			return nil, fmt.Errorf("malformatted PK token headers: %w", err)
		}

		alg = origHeaders.Algorithm()
		if alg != jwa.RS256 {
			return nil, fmt.Errorf("expected original headers to contain RS256 alg, got %s", alg)
		}

		kid = origHeaders.KeyID()
	} else {
		kid = pkt.Op.ProtectedHeaders().KeyID()
	}

	issuer, err := pkt.Issuer()
	if err != nil {
		return nil, err
	}

	return v.options.DiscoverPublicKey(ctx, kid, issuer)
}

func (v *ProviderVerifier) verifyCommitment(pkt *pktoken.PKToken) error {
	var claims map[string]any
	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		return err
	}

	cic, err := pkt.GetCicValues()
	if err != nil {
		return err
	}
	expectedCommitment, err := cic.Hash()
	if err != nil {
		return err
	}
	commitment, ok := claims[v.commitmentClaim]
	if !ok {
		return fmt.Errorf("missing commitment claim %s", v.commitmentClaim)
	}

	if commitment != string(expectedCommitment) {
		return fmt.Errorf("nonce claim doesn't match, got %q, expected %s", commitment, string(expectedCommitment))
	}
	return nil
}

func VerifyGQSig(ctx context.Context, pkt *pktoken.PKToken) error {
	alg, ok := pkt.ProviderAlgorithm()
	if !ok {
		return fmt.Errorf("missing provider algorithm header")
	}

	if alg != gq.GQ256 {
		return fmt.Errorf("signature is not of type GQ")
	}

	origHeaders, err := originalTokenHeaders(pkt)
	if err != nil {
		return fmt.Errorf("malformatted PK token headers: %w", err)
	}

	alg = origHeaders.Algorithm()
	if alg != jwa.RS256 {
		return fmt.Errorf("expected original headers to contain RS256 alg, got %s", alg)
	}

	issuer, err := pkt.Issuer()
	if err != nil {
		return fmt.Errorf("missing issuer: %w", err)
	}

	jwkKey, err := DiscoverProviderPublicKey(ctx, origHeaders.KeyID(), issuer)
	if err != nil {
		return fmt.Errorf("failed to get provider public key: %w", err)
	}

	if jwkKey.Algorithm() != jwa.RS256 {
		return fmt.Errorf("expected alg to be RS256 in JWK with kid %q for OP %q, got %q", origHeaders.KeyID(), issuer, jwkKey.Algorithm())
	}

	pubKey := new(rsa.PublicKey)
	err = jwkKey.Raw(pubKey)
	if err != nil {
		return fmt.Errorf("failed to decode public key: %w", err)
	}

	token, err := pkt.Compact(pkt.Op)
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

func originalTokenHeaders(pkt *pktoken.PKToken) (jws.Headers, error) {
	opHeaders := pkt.Op.ProtectedHeaders()
	if opHeaders.Algorithm() != gq.GQ256 {
		return nil, fmt.Errorf("expected GQ256 alg, got %s", opHeaders.Algorithm())
	}

	opToken, err := pkt.Compact(pkt.Op)
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
	case []any:
		for _, audience := range aud {
			if audience.(string) == clientID {
				return nil
			}
		}
		return fmt.Errorf("audience does not contain clientID %s, aud = %v", clientID, aud)
	default:
		return fmt.Errorf("missing audience claim")
	}
	return nil
}

func DiscoverProviderPublicKey(ctx context.Context, kid string, issuer string) (jwk.Key, error) {
	discConf, err := oidcclient.Discover(issuer, http.DefaultClient)
	if err != nil {
		return nil, fmt.Errorf("failed to call OIDC discovery endpoint: %w", err)
	}

	jwks, err := jwk.Fetch(ctx, discConf.JwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch to JWKS: %w", err)
	}

	key, ok := jwks.LookupKeyID(kid)
	if !ok {
		return nil, fmt.Errorf("key %s isn't in JWKS", kid)
	}

	return key, err
}
