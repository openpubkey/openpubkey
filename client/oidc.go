package client

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/awnumar/memguard"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
)

const GQSecurityParameter = 256

var ErrNonGQUnsupported = fmt.Errorf("non-GQ signatures are not supported")

// Interface for interacting with the OP (OpenID Provider)
type OpenIdProvider interface {
	RequestTokens(ctx context.Context, cicHash string) (*memguard.LockedBuffer, error)
	PublicKey(ctx context.Context, idt []byte) (crypto.PublicKey, error)
	VerifyCICHash(ctx context.Context, idt []byte, expectedCICHash string) error
	VerifyNonGQSig(ctx context.Context, idt []byte, expectedNonce string) error
	GetIssuer() string
}

// Interface for interacting with the OP (OpenID Provider)
type BrowserOpenIdProvider interface {
	OpenIdProvider
	HookHTTPSession(h HttpSessionHook)
}
type HttpSessionHook func(w http.ResponseWriter, r *http.Request)

func VerifyPKToken(ctx context.Context, pkt *pktoken.PKToken, provider OpenIdProvider) error {
	return PKTokenVerifer{
		AllowedProviders: []OpenIdProvider{provider},
	}.Verify(ctx, pkt)
}

type PKTokenVerifer struct {
	AllowedProviders []OpenIdProvider
	AllowedCosigners []CosignerProvider
}

func (v PKTokenVerifer) Verify(ctx context.Context, pkt *pktoken.PKToken) error {
	var pktOp struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(pkt.Payload, &pktOp); err != nil {
		return err
	}
	var provider OpenIdProvider
	for _, allowedOp := range v.AllowedProviders {
		if allowedOp.GetIssuer() == pktOp.Issuer {
			provider = allowedOp
			break
		}
	}
	if provider == nil {
		return fmt.Errorf("the OP issuer (%s) in the PK Token is not an allowed issuer", pktOp.Issuer)
	}

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
		// TODO: this needs to get the public key from a log of historic public keys based on the iat time in the token
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

	// If no cosigner is set, then we don't require a cosigner.
	if len(v.AllowedCosigners) != 0 {
		var cos *CosignerProvider
		if cosIss, ok := pkt.Cos.ProtectedHeaders().Get("iss"); !ok {
			return fmt.Errorf("no COS issuer set in the PK Token")
		} else {
			for _, allowedCos := range v.AllowedCosigners {
				if allowedCos.GetIssuer() == cosIss {
					cos = &allowedCos
					break
				}
			}
			if cos == nil {
				return fmt.Errorf("the COS issuer (%s) in the PK Token is not an list of allowed issuers", cosIss)
			}
		}
		if pkt.Cos != nil {
			if err := pkt.VerifyCosignerSignature(); err != nil {
				return fmt.Errorf("error verify cosigner signature on PK Token: %w", err)
			}
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
