package pktoken

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/util"
)

type CosignerClaims struct {
	Iss         string `json:"iss"`
	KeyID       string `json:"kid"`
	Algorithm   string `json:"alg"`
	AuthID      string `json:"eid"`
	AuthTime    int64  `json:"auth_time"`
	IssuedAt    int64  `json:"iat"` // may differ from auth_time because of refresh
	Expiration  int64  `json:"exp"`
	RedirectURI string `json:"ruri"`
	Nonce       string `json:"nonce"`
}

func ParseCosignerClaims(protected []byte) (*CosignerClaims, error) {
	var claims CosignerClaims
	if err := json.Unmarshal(protected, &claims); err != nil {
		return nil, err
	}

	// Check that all fields are present
	var missing []string
	if claims.Iss == "" {
		missing = append(missing, `iss`)
	}
	if claims.KeyID == "" {
		missing = append(missing, `kid`)
	}
	if claims.Algorithm == "" {
		missing = append(missing, `alg`)
	}
	if claims.AuthID == "" {
		missing = append(missing, `eid`)
	}
	if claims.AuthTime == 0 {
		missing = append(missing, `auth_time`)
	}
	if claims.IssuedAt == 0 {
		missing = append(missing, `iat`)
	}
	if claims.Expiration == 0 {
		missing = append(missing, `exp`)
	}
	if claims.RedirectURI == "" {
		missing = append(missing, `ruri`)
	}
	if claims.Nonce == "" {
		missing = append(missing, `nonce`)
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("cosigner protect header missing required headers: %v", missing)
	}

	return &claims, nil
}

func (p *PKToken) VerifyCosignerSignature() error {
	if p.Cos == nil {
		return fmt.Errorf("no cosigner signature")
	}

	cosToken, err := p.Compact(p.Cos)
	if err != nil {
		return err
	}

	// Parse our header
	rawHeader, _, _, err := jws.SplitCompact(cosToken)
	if err != nil {
		return err
	}
	decodedHeader, err := util.Base64DecodeForJWT(rawHeader)
	if err != nil {
		return err
	}
	header, err := ParseCosignerClaims(decodedHeader)
	if err != nil {
		return err
	}

	// Check if it's expired
	if time.Now().After(time.Unix(header.Expiration, 0)) {
		return fmt.Errorf("cosigner signature expired")
	}

	// Grab the public keys from the JWKS endpoint
	jwksUrl, err := url.ParseRequestURI(header.Iss)
	if err != nil {
		return err
	}
	jwksUrl.Path = `/.well-known/jwks.json`
	// TODO: verify scheme matches some expected value

	set, err := jwk.Fetch(context.Background(), jwksUrl.String())
	if err != nil {
		return fmt.Errorf("failed to fetch public keys from Cosigner JWKS endpoint")
	}

	key, ok := set.LookupKeyID(header.KeyID)
	if !ok {
		return fmt.Errorf("missing key id")
	}

	_, err = jws.Verify(cosToken, jws.WithKey(jwa.KeyAlgorithmFrom(header.Algorithm), key))
	return err
}
