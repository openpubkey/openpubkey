package mfa

import (
	"crypto"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
)

type Protocol string

const (
	TOTP     Protocol = "totp"
	WebAuthn Protocol = "webauthn"
)

type Claims struct {
	ID          string `json:"csid"`
	KeyID       string `json:"kid"`
	Algorithm   string `json:"alg"`
	AuthID      string `json:"eid"`
	AuthTime    int64  `json:"auth_time"`
	IssuedAt    int64  `json:"iat"` // may differ from auth_time because of refresh
	Expiration  int64  `json:"exp"`
	RedirectURI string `json:"ruri"`
}

type Cosigner struct {
	csid string
	kid  string

	alg    jwa.SignatureAlgorithm
	signer crypto.Signer

	jwkKey jwk.Key

	// The MFA in MFACosigner, we use this to authenticate the user
	mfa MFA
}

type MFA interface {
	Authenticate(pkt *pktoken.PKToken) error
	URI() string
}

func NewCosigner(authenticator MFA) (*Cosigner, error) {
	// Generate the key pair for our cosigner
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	if err != nil {
		return nil, err
	}

	cosigner := &Cosigner{
		kid:    "first-key",
		alg:    alg,
		signer: signer,
		mfa:    authenticator,
	}

	if err := cosigner.hostJWKS(); err != nil {
		return nil, err
	}

	return cosigner, nil
}

func (c *Cosigner) Cosign(pkt *pktoken.PKToken) error {
	if err := c.mfa.Authenticate(pkt); err != nil {
		return err
	}

	protected := Claims{
		ID:          c.csid,
		KeyID:       c.kid,
		Algorithm:   c.alg.String(),
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

	// Now that our mfa has authenticated the user, we can sign using our key
	return pkt.Sign(pktoken.Cos, c.signer, c.alg, headers)
}

func (c *Cosigner) hostJWKS() error {
	// Generate our JWKS using our signing key
	jwkKey, err := jwk.PublicKeyOf(c.signer)
	if err != nil {
		return err
	}
	jwkKey.Set(jwk.AlgorithmKey, c.alg)
	jwkKey.Set(jwk.KeyIDKey, c.kid)

	// Find an empty port
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return fmt.Errorf("failed to bind to an available port: %w", err)
	}

	// Host our JWKS at a localhost url
	http.HandleFunc("/.well-known/jwks.json", c.printJWKS)
	go func() {
		http.Serve(listener, nil)
	}()

	c.csid = fmt.Sprintf("localhost:%d", listener.Addr().(*net.TCPAddr).Port)
	fmt.Printf("JWKS hosted at http://%s/.well-known/jwks.json\n", c.csid)

	return nil
}

func (c *Cosigner) printJWKS(w http.ResponseWriter, r *http.Request) {
	keySet := jwk.NewSet()
	keySet.AddKey(c.jwkKey)

	data, err := json.MarshalIndent(keySet, "", "  ")
	if err != nil {
		http.Error(w, "Failed to marshal JWKS", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}
