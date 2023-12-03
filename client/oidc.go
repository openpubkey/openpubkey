package client

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"fmt"

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
	RequestTokensCos(ctx context.Context, cicHash string, oidcEnder HttpSessionHook) (*OidcDone, error)
	PublicKey(ctx context.Context, idt []byte) (crypto.PublicKey, error)
	VerifyCICHash(ctx context.Context, idt []byte, expectedCICHash string) error
	VerifyNonGQSig(ctx context.Context, idt []byte, expectedNonce string) error
}

// Interface for interacting with the OP (OpenID Provider)
type BrowserOpenIdProvider interface {
	OpenIdProvider
	HookHTTPSession(h HttpSessionHook)
}

type OidcDone struct {
	Token *memguard.LockedBuffer
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
		// TODO: this needs to get the public key from a log of historic public keys based on the iat time in the token
		pubKey, err := provider.PublicKey(ctx, idt)
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
