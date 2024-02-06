package reader

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type JWKSObj struct {
	Fields struct {
		Epoch string `json:"epoch"`
		Jwk   struct {
			Fields map[string]string `json:"fields"`
		} `json:"jwk"`
		JwkId struct {
			Type   string `json:"type"`
			Fields struct {
				Issuer string `json:"iss"`
				KeyID  string `json:"kid"`
			} `json:"fields"`
		} `json:"jwk_id"`
	} `json:"fields"`
}

type Content struct {
	Fields struct {
		Value struct {
			Fields struct {
				ActiveJwks []JWKSObj `json:"active_jwks"`
			} `json:"fields"`
		} `json:"value"`
	} `json:"fields"`
}

type Jwksdump struct {
	LatestObj struct {
		Objid string  `json:"objectId"`
		Cnt   Content `json:"content"`
	} `json:"latest-obj"`
	PastObj []struct {
		Details struct {
			Content Content `json:"content"`
		} `json:"details"`
	} `json:"past-objs"`
}

type JwksState struct {
	Epoch     string
	Publickey jwk.Key
}

type IssKidKey struct {
	Issuer string // ID Token issuer (iss)
	KeyId  string // ID Token audience (aud)
}

type JwksData struct {
	JwksMap       map[string][]JwksState
	JwksIssKidMap map[IssKidKey]JwksState
}

func (d *JwksData) Print() {
	for k, v := range d.JwksMap {
		fmt.Println(k, len(v))
	}
}

func (d *JwksData) Add(iss string, kid string, epoch string, jwkJson []byte) error {

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

	if _, ok := d.JwksIssKidMap[IssKidKey{Issuer: iss, KeyId: key.KeyID()}]; ok {
		// TODO: Check for iss and kids collisions with different keys
	}

	d.JwksIssKidMap[IssKidKey{Issuer: iss, KeyId: kid}] = jwksState

	return nil
}

func (d *JwksData) processJWKS(jwksObjs []JWKSObj) error {

	for _, jwksObj := range jwksObjs {
		jwkMeta := jwksObj.Fields
		jwkfields := jwkMeta.Jwk.Fields

		jwkJson, err := json.Marshal(jwkfields)
		if err != nil {
			return err
		}

		epoch := jwkMeta.Epoch
		jwkIss := jwkMeta.JwkId.Fields.Issuer
		jwkKid := jwkMeta.JwkId.Fields.KeyID
		d.Add(jwkIss, jwkKid, epoch, jwkJson)

	}

	return nil
}

func read() error {
	jwksDb := JwksData{
		JwksMap: map[string][]JwksState{},
	}

	fpath := "oppubkeys100.json"
	f, err := os.Open(fpath)
	if err != nil {
		return err
	}

	jsonBytes, err := io.ReadAll(f)
	defer f.Close()

	var result Jwksdump
	err = json.Unmarshal(jsonBytes, &result)
	if err != nil {
		return err
	}
	err = jwksDb.processJWKS(result.LatestObj.Cnt.Fields.Value.Fields.ActiveJwks)
	if err != nil {
		return err
	}

	for _, pastObj := range result.PastObj {
		err = jwksDb.processJWKS(pastObj.Details.Content.Fields.Value.Fields.ActiveJwks)
		if err != nil {
			return err
		}
	}
	jwksDb.Print()

	return nil
}
