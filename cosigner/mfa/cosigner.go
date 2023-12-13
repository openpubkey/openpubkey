package mfa

import (
	"crypto"
	"encoding/json"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/pktoken"
)

type Cosigner struct {
	issuer string
	keyID  string
	alg    jwa.KeyAlgorithm
	signer crypto.Signer

	// The MFA in MFACosigner, we use this to authenticate the user
	mfa Authenticator
}

type Authenticator interface {
	Authenticate(pkt *pktoken.PKToken) error
	URI() string
}

func NewCosigner(signer crypto.Signer, alg jwa.SignatureAlgorithm, issuer, keyID string, authenticator Authenticator) (*Cosigner, error) {
	return &Cosigner{
		issuer: issuer,
		keyID:  keyID,
		alg:    alg,
		signer: signer,
		mfa:    authenticator,
	}, nil
}

func (c *Cosigner) Cosign(pkt *pktoken.PKToken) error {
	if err := c.mfa.Authenticate(pkt); err != nil {
		return err
	}

	protected := pktoken.CosignerClaims{
		ID:          c.issuer,
		KeyID:       c.keyID,
		Algorithm:   c.alg.String(),
		AuthID:      "12345678",
		AuthTime:    time.Now().Unix(),
		IssuedAt:    time.Now().Unix(),
		Expiration:  time.Now().Add(time.Hour).Unix(),
		RedirectURI: c.mfa.URI(),
	}

	jsonBytes, err := json.Marshal(protected)
	if err != nil {
		return err
	}

	var headers map[string]any
	if err := json.Unmarshal(jsonBytes, &headers); err != nil {
		return err
	}

	// Now that our mfa has authenticated the user, we can add our signature
	return pkt.Sign(pktoken.COS, c.signer, c.alg, headers)
}
