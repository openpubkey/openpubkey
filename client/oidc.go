package client

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/awnumar/memguard"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
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
	RequestTokens(ctx context.Context, cicHash string) (*memguard.LockedBuffer, error)
	PublicKey(ctx context.Context, idt []byte) (crypto.PublicKey, error)
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

	sigType, ok := pkt.ProviderSignatureType()
	if !ok {
		return fmt.Errorf("provider signature type missing")
	}

	switch sigType {
	case pktoken.Gq:
		origHeaders, err := gq.OriginalJWTHeaders(idt)
		if err != nil {
			return err
		}

		fmt.Println(string(origHeaders))

		// TODO: this needs to get the public key from a log of historic public keys based on the iat time in the token
		pubKey, err := provider.PublicKey(ctx, origHeaders)
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
	case pktoken.Oidc:
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

func ExtractClaim(idt []byte, claimName string) (string, error) {
	_, payloadB64, _, err := jws.SplitCompact(idt)
	if err != nil {
		return "", fmt.Errorf("failed to split/decode JWT: %w", err)
	}

	payloadJSON, err := util.Base64DecodeForJWT(payloadB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode payload")
	}

	var payload map[string]any
	err = json.Unmarshal(payloadJSON, &payload)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal payload")
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
