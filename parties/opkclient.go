package parties

import (
	"crypto/ecdsa"
	"fmt"
	"io"
	"net/http"

	"github.com/sirupsen/logrus"
	"github.com/zitadel/oidc/v2/pkg/oidc"

	"github.com/bastionzero/openpubkey/pktoken"
)

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
		pktCom := pkt.ToCompact()
		fmt.Printf("PKT=%s", pktCom)
		o.Op.VerifyPKToken(pktCom, nil)
		err = o.Signer.WriteToFile(pktCom)
		if err != nil {
			logrus.Fatalf("Error creating PK Token: %s", err.Error())
			return
		}
	}
	o.Op.RequestTokens(nonce, receiveIDTHandler)
}

type TokenCallback func(tokens *oidc.Tokens[*oidc.IDTokenClaims])

// Interface for interacting with the OP (OpenID Provider)
type OpenIdProvider interface {
	RequestTokens(cicHash string, cb TokenCallback) error
	VerifyPKToken(pktCom []byte, cosPk *ecdsa.PublicKey) error
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
