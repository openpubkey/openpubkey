package parties

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"
	"net/http"

	"github.com/sirupsen/logrus"
	"github.com/zitadel/oidc/v2/pkg/oidc"

	"github.com/bastionzero/openpubkey/gq"
	"github.com/bastionzero/openpubkey/pktoken"
)

const gqSecurityParameter = 256

// Interface for interacting with the MFA Cosigner (MFACos)
type MFACos interface {
	// place holder for MFA Cosigner
	// TODO: Add MFA Cosigner
}

type OpkClient struct {
	PktCom      []byte
	Signer      *pktoken.Signer
	Op          OpenIdProvider
	MFACosigner MFACos
}

func (o *OpkClient) OidcAuth() {
	nonce := o.Signer.GetNonce()
	receiveIDTHandler := func(tokens *oidc.Tokens[*oidc.IDTokenClaims]) {
		idt := []byte(tokens.IDToken)
		pkt, err := o.Signer.CreatePkToken(idt)
		if err != nil {
			logrus.Fatalf("Error creating PK Token: %s", err.Error())
			return
		}

		if o.Signer.GqSig {
			opKey, err := o.Op.PublicKey(idt)
			if err != nil {
				logrus.Fatalf("Error getting OP public key: %s", err.Error())
				return
			}
			rsaPubKey := opKey.(*rsa.PublicKey)

			sv := gq.NewSignerVerifier(rsaPubKey, gqSecurityParameter)
			gqSig, err := sv.SignJWTIdentity(idt)
			if err != nil {
				logrus.Fatalf("Error creating GQ signature: %s", err.Error())
				return
			}

			pkt.OpSig = gqSig
			pkt.OpSigGQ = true
			// TODO: make sure old value of OpSig is fully gone from memory
		}

		pktJSON, err := pkt.ToJSON()
		if err != nil {
			logrus.Fatalf("Error serializing PK Token: %s", err.Error())
			return
		}
		fmt.Printf("PKT=%s\n", pktJSON)
		o.Op.VerifyPKToken(pktJSON, nil)
		err = o.Signer.WriteToFile(pktJSON)
		if err != nil {
			logrus.Fatalf("Error creating PK Token: %s", err.Error())
			return
		}
	}
	o.Op.RequestTokens(nonce, receiveIDTHandler)
}

type TokenCallback func(tokens *oidc.Tokens[*oidc.IDTokenClaims])

type PublicKey interface {
	Equal(x crypto.PublicKey) bool
}

// Interface for interacting with the OP (OpenID Provider)
type OpenIdProvider interface {
	RequestTokens(cicHash string, cb TokenCallback) error
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
