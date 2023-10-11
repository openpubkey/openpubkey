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
	PktCom      []byte
	Gq          bool
	Op          OpenIdProvider
	MFACosigner MFACos
}

func (o *OpkClient) OidcAuth() ([]byte, error) {
	nonce, err := cic.Commitment()
	if err != nil {
		return nil, fmt.Errorf("error getting nonce: %w", err)
	}

	idToken, err := o.Op.RequestTokens(nonce)
	if err != nil {
		return nil, fmt.Errorf("error requesting ID Token: %w", err)
	}

	cicToken, err := cic.Sign(signer, idToken)
	if err != nil {
		return nil, fmt.Errorf("error creating cic token: %w", err)
	}

	pkt, err := pktoken.New(idToken, cicToken)
	if err != nil {
		return nil, fmt.Errorf("error creating PK Token: %w", err)
	}

	if o.Gq {
		opKey, err := o.Op.PublicKey(idToken)
		if err != nil {
			return nil, fmt.Errorf("error getting OP public key: %w", err)
		}
		rsaPubKey := opKey.(*rsa.PublicKey)

		sv := gq.NewSignerVerifier(rsaPubKey, gqSecurityParameter)
		gqSig, err := sv.SignJWTIdentity(idToken)
		if err != nil {
			return nil, fmt.Errorf("error creating GQ signature: %w", err)
		}

		pkt.OpSig = gqSig
		pkt.OpSigGQ = true
		// TODO: make sure old value of OpSig is fully gone from memory
	}

	pktJSON, err := pkt.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("error serializing PK Token: %w", err)
	}
	fmt.Printf("PKT=%s\n", pktJSON)
	_, err = o.Op.VerifyPKToken(pktJSON, nil)
	if err != nil {
		return nil, fmt.Errorf("error verifying PK Token: %w", err)
	}
	return pktJSON, nil
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
	uri := fmt.Sprintf("http://localhost:3002/cert?pkt=%s", o.PktCom)
	resp, err := http.Get(uri)
	if err != nil {
		fmt.Printf("MFA request failed: %v\n", err)
		return nil, err
	}
	defer resp.Body.Close()
	certBytes, err := io.ReadAll(resp.Body)
	return certBytes, nil
}
