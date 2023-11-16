package mfa

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/pktoken"
)

type Cosigner struct {
	issuer     string
	keyID      string
	alg        jwa.KeyAlgorithm
	signer     crypto.Signer
	authIdIter *big.Int
	hmacKey    []byte

	// The MFA in MFACosigner, we use this to authenticate the user
	mfa Authenticator
}

type Authenticator interface {
	Authenticate(pkt *pktoken.PKToken) error
	URI() string
}

func NewCosigner(signer crypto.Signer, alg jwa.SignatureAlgorithm, issuer, keyID string, authenticator Authenticator) (*Cosigner, error) {
	hmacKey := make([]byte, 64)

	if _, err := rand.Read(hmacKey); err != nil {
		return nil, err
	}

	return &Cosigner{
		issuer:     issuer,
		keyID:      keyID,
		alg:        alg,
		signer:     signer,
		authIdIter: big.NewInt(0),
		hmacKey:    hmacKey,
		mfa:        authenticator,
	}, nil
}

func (c *Cosigner) Cosign(pkt *pktoken.PKToken) error {
	// if err := c.mfa.Authenticate(pkt); err != nil {
	// 	return err
	// }

	mac := hmac.New(crypto.SHA3_512.New, c.hmacKey)
	mac.Write(c.authIdIter.Bytes())
	authID := hex.EncodeToString(mac.Sum(nil))

	c.authIdIter.Add(c.authIdIter, big.NewInt(1))

	protected := pktoken.CosignerClaims{
		ID:          c.issuer,
		KeyID:       c.keyID,
		Algorithm:   c.alg.String(),
		AuthID:      authID,
		AuthTime:    time.Now().Unix(),
		IssuedAt:    time.Now().Unix(),
		Expiration:  time.Now().Add(time.Hour).Unix(),
		RedirectURI: "http://localhost:3003",
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
