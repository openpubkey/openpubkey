package client

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/awnumar/memguard"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
	oidcclient "github.com/zitadel/oidc/v2/pkg/client"
)

const GQSecurityParameter = 256

var ErrNonGQUnsupported = fmt.Errorf("non-GQ signatures are not supported")

type OidcClaims struct {
	Issuer     string `json:"iss"`
	Subject    string `json:"sub"`
	Audience   string `json:"-"`
	Expiration int64  `json:"exp"`
	IssuedAt   int64  `json:"iat"`
	Email      string `json:"email,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
	Username   string `json:"preferred_username,omitempty"`
	FirstName  string `json:"given_name,omitempty"`
	LastName   string `json:"family_name,omitempty"`
}

// Implement UnmarshalJSON for custom handling during JSON unmarshaling
func (id *OidcClaims) UnmarshalJSON(data []byte) error {
	// unmarshal audience claim seperately to account for []string, https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
	type Alias OidcClaims
	aux := &struct {
		Audience any `json:"aud"`
		*Alias
	}{
		Alias: (*Alias)(id),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	switch t := aux.Audience.(type) {
	case string:
		id.Audience = t
	case []any:
		audList := []string{}
		for _, v := range t {
			audList = append(audList, v.(string))
		}
		id.Audience = strings.Join(audList, ",")
	default:
		id.Audience = ""
	}

	return nil
}

// Interface for interacting with the OP (OpenID Provider)
type OpenIdProvider interface {
	Issuer() string
	RequestTokens(ctx context.Context, cicHash string) (*memguard.LockedBuffer, error)
	PublicKey(ctx context.Context, headers map[string]any) (crypto.PublicKey, error)
	VerifyCICHash(ctx context.Context, idt []byte, expectedCICHash string) error
	VerifyNonGQSig(ctx context.Context, idt []byte, expectedNonce string) error
}

func VerifyPKToken(ctx context.Context, pkt *pktoken.PKToken, provider OpenIdProvider) error {
	cic, err := pkt.GetCicValues()
	if err != nil {
		return err
	}

	commitment, err := cic.Hash()
	if err != nil {
		return err
	}

	idt, err := pkt.Compact(pkt.Op)
	if err != nil {
		return fmt.Errorf("")
	}

	alg, ok := pkt.ProviderAlgorithm()
	if !ok {
		return fmt.Errorf("provider signature type missing")
	}

	switch alg {
	case gq.GQ256:
		origHeaders, err := gq.OriginalJWTHeaders(idt)
		if err != nil {
			return err
		}

		origHeaderClaims, err := parseJWTSegment(origHeaders)
		if err != nil {
			return err
		}

		algClaim, ok := origHeaderClaims["alg"]
		if !ok {
			return fmt.Errorf("missing alg claim")
		}

		alg, ok := algClaim.(string)
		if !ok {
			return fmt.Errorf("expected alg claim to contain a SignatureAlgorithm, got %T", algClaim)
		}

		if jwa.SignatureAlgorithm(alg) != jwa.RS256 {
			return fmt.Errorf("expected original headers to contain RS256 alg, got %s", alg)
		}

		// TODO: this needs to get the public key from a log of historic public keys based on the iat time in the token
		pubKey, err := provider.PublicKey(ctx, origHeaderClaims)
		if err != nil {
			return fmt.Errorf("failed to get OP public key: %w", err)
		}

		rsaPubKey := pubKey.(*rsa.PublicKey)

		err = pkt.VerifyGQSig(rsaPubKey, GQSecurityParameter)
		if err != nil {
			return fmt.Errorf("error verifying OP GQ signature on PK Token: %w", err)
		}

		err = provider.VerifyCICHash(ctx, idt, string(commitment))
		if err != nil {
			return fmt.Errorf("failed to verify CIC hash: %w", err)
		}
	case jwa.RS256:
		err = provider.VerifyNonGQSig(ctx, idt, string(commitment))
		if err != nil {
			if err == ErrNonGQUnsupported {
				return fmt.Errorf("oidc provider doesn't support non-GQ signatures")
			}
			return fmt.Errorf("failed to verify signature from OIDC provider: %w", err)
		}
	}

	err = pkt.VerifyCicSig()
	if err != nil {
		return fmt.Errorf("error verifying CIC signature on PK Token: %w", err)
	}

	if pkt.Cos != nil {
		if err := pkt.VerifyCosignerSignature(); err != nil {
			return fmt.Errorf("error verify cosigner signature on PK Token: %w", err)
		}
	}

	return nil
}

func DiscoverPublicKey(ctx context.Context, headers map[string]any, issuer string) (crypto.PublicKey, error) {
	kidRaw, ok := headers["kid"]
	if !ok {
		return nil, fmt.Errorf("missing kid claim")
	}

	kid, ok := kidRaw.(string)
	if !ok {
		return nil, fmt.Errorf("expected kid claim to be a string, got %T", kidRaw)
	}

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
		return nil, fmt.Errorf("key %q isn't in JWKS", kid)
	}

	pubKey := new(rsa.PublicKey)
	err = key.Raw(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	return pubKey, err
}

func ExtractClaim(idt []byte, claimName string) (string, error) {
	_, payloadB64, _, err := jws.SplitCompact(idt)
	if err != nil {
		return "", fmt.Errorf("failed to split/decode JWT: %w", err)
	}

	payload, err := parseJWTSegment(payloadB64)
	if err != nil {
		return "", err
	}

	claim, ok := payload[claimName]
	if !ok {
		return "", fmt.Errorf("claim '%s' missing from payload", claimName)
	}

	claimStr, ok := claim.(string)
	if !ok {
		return "", fmt.Errorf("expected claim '%s' to be a string, was %T", claimName, claim)
	}

	return claimStr, nil
}

func parseJWTSegment(segment []byte) (map[string]any, error) {
	segmentJSON, err := util.Base64DecodeForJWT(segment)
	if err != nil {
		return nil, fmt.Errorf("error decoding segment: %w", err)
	}

	claims := make(map[string]any)
	err = json.Unmarshal(segmentJSON, &claims)
	if err != nil {
		return nil, fmt.Errorf("error parsing segment: %w", err)
	}

	return claims, nil
}
