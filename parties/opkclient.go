package parties

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"
	"net/http"

	"github.com/zitadel/oidc/v2/pkg/oidc"

	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/pktoken"
)

const gqSecurityParameter = 256

// Interface for interacting with the MFA Cosigner (MFACos)
type MFACos interface {
	// place holder for MFA Cosigner
	// TODO: Add MFA Cosigner
}

type OpkClient struct {
	PktJson     []byte
	Signer      *pktoken.Signer
	Op          OpenIdProvider
	MFACosigner MFACos
}

func (o *OpkClient) OidcAuth() ([]byte, error) {
	nonce, err := o.Signer.GetNonce()
	if err != nil {
		return nil, fmt.Errorf("error getting nonce: %w", err)
	}
	idt, err := o.Op.RequestTokens(nonce)
	if err != nil {
		return nil, fmt.Errorf("error requesting ID Token: %w", err)
	}
	pkt, err := o.Signer.CreatePkToken(idt)
	if err != nil {
		return nil, fmt.Errorf("error creating PK Token: %w", err)
	}

	if o.Signer.GqSig {
		opKey, err := o.Op.PublicKey(idt)
		if err != nil {
			return nil, fmt.Errorf("error getting OP public key: %w", err)
		}
		rsaPubKey := opKey.(*rsa.PublicKey)

		sv := gq.NewSignerVerifier(rsaPubKey, gqSecurityParameter)
		gqSig, err := sv.SignJWTIdentity(idt)
		if err != nil {
			return nil, fmt.Errorf("error creating GQ signature: %w", err)
		}

		pkt.OpSig = gqSig
		pkt.OpSigGQ = true
		// TODO: make sure old value of OpSig is fully gone from memory
	}

	o.PktJson, err = pkt.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("error serializing PK Token: %w", err)
	}

	_, err = o.Op.VerifyPKToken(o.PktJson, nil)
	if err != nil {
		return nil, fmt.Errorf("error verifying PK Token: %w", err)
	}

	return o.PktJson, nil
}

type TokenCallback func(tokens *oidc.Tokens[*oidc.IDTokenClaims])

type PublicKey interface {
	Equal(x crypto.PublicKey) bool
}

// Interface for interacting with the OP (OpenID Provider)
type OpenIdProvider interface {
	RequestTokens(cicHash string) ([]byte, error)
	VerifyPKToken(pktJSON []byte, cosPk *ecdsa.PublicKey) (map[string]any, error)
	PublicKey(idt []byte) (PublicKey, error)
}

func (o *OpkClient) RequestCert() ([]byte, error) {
	uri := fmt.Sprintf("http://localhost:3002/cert?pkt=%s", o.PktJson)
	resp, err := http.Get(uri)
	if err != nil {
		return nil, fmt.Errorf("MFA request failed: %s", err)
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
