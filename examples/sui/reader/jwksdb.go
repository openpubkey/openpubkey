package reader

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type JwksState struct {
	Epoch     string
	Publickey jwk.Key
}

type IssKidKey struct {
	Issuer string // ID Token issuer (iss)
	KeyId  string // ID Token audience (aud)
}

type JwksDb struct {
	JwksMap       map[string][]JwksState
	JwksIssKidMap map[IssKidKey]JwksState
}

func (d *JwksDb) Print() {
	for k, v := range d.JwksMap {
		fmt.Println(k, len(v))
	}
}

func (d *JwksDb) Add(iss string, kid string, epoch string, jwkJson []byte) error {

	key, err := jwk.ParseKey(jwkJson)
	if err != nil {
		return err
	}

	jwksState := JwksState{
		Epoch:     epoch,
		Publickey: key,
	}

	jwksOP, ok := d.JwksMap[iss]
	if !ok {
		jwksOP = []JwksState{}
	}
	jwksOP = append(jwksOP, jwksState)
	d.JwksMap[iss] = jwksOP

	if d.JwksIssKidMap == nil {
		d.JwksIssKidMap = map[IssKidKey]JwksState{}
	}

	if _, ok := d.JwksIssKidMap[IssKidKey{Issuer: iss, KeyId: kid}]; ok {
		existingKey := d.JwksIssKidMap[IssKidKey{Issuer: iss, KeyId: kid}].Publickey
		if existingKey.X509CertThumbprintS256() != key.X509CertThumbprintS256() {
			// This shouldn't happen, kids (key ids) are intended to unique
			// identifiers of keys within a issuer. A collision in which two
			// different keys from the same issuer and share the same kid means
			// something has gone truly wrong at the OpenID Provider or this code
			// has a bug.
			return fmt.Errorf("two different keys have the same iss (%s) and key (%s)", iss, kid)
		}
	}
	d.JwksIssKidMap[IssKidKey{Issuer: iss, KeyId: kid}] = jwksState

	return nil
}
