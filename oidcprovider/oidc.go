package oidcprovider

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/openpubkey/openpubkey/pktoken"
)

const gqSecurityParameter = 256

type PublicKey interface {
	Equal(x crypto.PublicKey) bool
}

var ErrNonGQUnsupported = fmt.Errorf("non-GQ signatures are not supported")

// Interface for interacting with the OP (OpenID Provider)
type OpenIdProvider interface {
	RequestTokens(ctx context.Context, cicHash string) ([]byte, error)
	PublicKey(ctx context.Context, idt []byte) (PublicKey, error)
	NonceClaimName() string
	VerifyOIDCSig(ctx context.Context, idt []byte, expectedNonce string) error
}

func VerifyPKToken(ctx context.Context, pkt *pktoken.PKToken, provider OpenIdProvider, cosPk crypto.PublicKey) error {
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

		err = pkt.VerifyGQSig(rsaPubKey, gqSecurityParameter)
		if err != nil {
			return fmt.Errorf("error verifying OP GQ signature on PK Token: %w", err)
		}

		var payload map[string]any
		err = json.Unmarshal(pkt.Payload, &payload)
		if err != nil {
			return fmt.Errorf("failed to unmarshal payload")
		}

		nonceClaimName := provider.NonceClaimName()
		nonce := payload[nonceClaimName]
		if nonce != string(commitment) {
			return fmt.Errorf("aud doesn't match, got %q, expected %q", nonce, string(commitment))
		}
	case pktoken.Oidc:
		err = provider.VerifyOIDCSig(ctx, idt, string(commitment))
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

	// Skip Cosigner signature verification if no cosigner pubkey is supplied
	if cosPk != nil {
		cosPkJwk, err := jwk.FromRaw(cosPk)
		if err != nil {
			return fmt.Errorf("error verifying CIC signature on PK Token: %w", err)
		}

		err = pkt.VerifyCosSig(cosPkJwk, jwa.KeyAlgorithmFrom("ES256"))
		if err != nil {
			return fmt.Errorf("error verify cosigner signature on PK Token: %w", err)
		}
	}

	return nil
}
