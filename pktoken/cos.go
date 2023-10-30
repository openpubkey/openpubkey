package pktoken

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

type CosPHeader struct {
	Alg       string
	Jwk       interface{}
	Kid       string
	Csid      string
	Eid       string
	Auth_time int64
	Iat       int64
	Exp       int64
	Mfa       string
	Ruri      string
}

func (p *PKToken) GetCosValues() (*CosPHeader, error) {
	if p.Cos == nil {
		return nil, fmt.Errorf("cos signature missing")
	}

	cosPH, err := p.Cos.ProtectedHeaders().AsMap(context.TODO())
	if err != nil {
		return nil, err
	}

	cosPHBytes, err := json.Marshal(cosPH)
	if err != nil {
		return nil, err
	}

	var hds *CosPHeader
	if err := json.Unmarshal(cosPHBytes, &hds); err != nil {
		return nil, err
	}

	return hds, nil
}

// TODO: Make this take a cosignerid and JWKS that we trust
func (p *PKToken) VerifyCosSig(cosPk jwk.Key, alg jwa.KeyAlgorithm) error {
	if p.Cos == nil {
		return fmt.Errorf("Failed to verify Cosigner signature as the Cosigner Signature is nil.")
	}

	message := jws.NewMessage().
		SetPayload(p.Payload).
		AppendSignature(p.Cic)
	cosJwsCom, err := jws.Compact(message)
	if err != nil {
		return err
	}

	_, err = jws.Verify(cosJwsCom, jws.WithKey(alg, cosPk))
	if err != nil {
		return err
	}

	hrs, err := p.GetCosValues()
	if err != nil {
		return err
	}

	// Expiration check
	if hrs.Exp < time.Now().Unix() {
		return fmt.Errorf("Cosigner Signature on PK Token is expired by %d seconds.", time.Now().Unix()-hrs.Exp)
	}

	// Check algorithms match
	if hrs.Alg != alg.String() {
		return fmt.Errorf("Algorithm in cosigner protected header, %s, does not match algorithm provided, %s.", hrs.Alg, alg)
	}

	cosPkBytes, err := json.Marshal(hrs.Jwk)
	if err != nil {
		return err
	}
	cosPkInPH, err := jwk.ParseKey(cosPkBytes)
	if err != nil {
		return err
	}
	if cosPkInPH.X509CertThumbprint() != cosPk.X509CertThumbprint() {
		return fmt.Errorf("JWK of cosigner public key in protected header, %v, does not match JWK public key provided, %v.", cosPkInPH, cosPk)
	}

	// verified
	return nil
}
