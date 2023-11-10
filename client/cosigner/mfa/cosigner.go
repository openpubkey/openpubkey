package mfa

import (
	"crypto"
	"encoding/json"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/pktoken"
)

type Protocol string

const (
	TOTP     Protocol = "totp"
	WebAuthn Protocol = "webauthn"
)

type Cosigner struct {
	csid string
	kid  string

	alg    jwa.KeyAlgorithm
	signer crypto.Signer

	// The MFA in MFACosigner, we use this to authenticate the user
	mfa MFA
}

type MFA interface {
	Authenticate(pkt *pktoken.PKToken) error
	URI() string
}

func NewCosigner(signer crypto.Signer, alg jwa.SignatureAlgorithm, csid, kid string, authenticator MFA) (*Cosigner, error) {
	return &Cosigner{
		csid:   csid,
		kid:    kid,
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
		ID:          c.csid,
		KeyID:       c.kid,
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
	return pkt.Sign(pktoken.Cos, c.signer, c.alg, headers)
}
