package reader

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/block-vision/sui-go-sdk/models"
	"github.com/block-vision/sui-go-sdk/sui"
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

type JwksKey struct {
	Iss    string
	Kid    string
	JwkKey jwk.Key
	Epoch  string
}

func NewJwksKey(jwksMap map[string]any) (*JwksKey, error) {

	epoch := jwksMap["fields"].(map[string]any)["epoch"].(string)

	jwkObj := jwksMap["fields"].(map[string]any)["jwk"].(map[string]any)["fields"]

	jwkJson, err := json.Marshal(jwkObj)
	if err != nil {
		return nil, err
	}

	key, err := jwk.ParseKey(jwkJson)
	if err != nil {
		return nil, err
	}

	jwkId := jwksMap["fields"].(map[string]any)["jwk_id"].(map[string]any)["fields"].(map[string]any)
	iss := jwkId["iss"].(string)
	kid := jwkId["kid"].(string)

	fmt.Println(epoch, jwkObj, jwkId, iss, kid, key)
	return &JwksKey{
		Iss:    iss,
		Kid:    kid,
		JwkKey: key,
		Epoch:  epoch,
	}, nil
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

func (j *Jwksdump) GetLatestJwks() []JWKSObj {
	return j.LatestObj.Cnt.Fields.Value.Fields.ActiveJwks
}

func (j *Jwksdump) GetListPastJwks() [][]JWKSObj {
	listPastJwks := [][]JWKSObj{}
	for _, pastObj := range j.PastObj {
		jwks := pastObj.Details.Content.Fields.Value.Fields.ActiveJwks
		listPastJwks = append(listPastJwks, jwks)
	}
	return listPastJwks
}

func processJWKS(d *JwksDb, jwksObjs []JWKSObj) error {

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
	jwksDb := JwksDb{
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
	err = processJWKS(&jwksDb, result.GetLatestJwks())
	if err != nil {
		return err
	}

	for _, pastObj := range result.GetListPastJwks() {
		// jwks := pastObj.Details.Content.Fields.Value.Fields.ActiveJwks
		err = processJWKS(&jwksDb, pastObj)
		if err != nil {
			return err
		}
	}
	jwksDb.Print()

	return nil
}

func DownloadFromSui() error {
	// jwksDb := JwksDb{
	// 	JwksMap: map[string][]JwksState{},
	// }

	var ctx = context.Background()
	var cli = sui.NewSuiClient("https://fullnode.mainnet.sui.io:443")

	objdata, err := cli.SuiGetObject(ctx,
		models.SuiGetObjectRequest{
			ObjectId: "0xcfecb053c69314e75f36561910f3535dd466b6e2e3593708f370e80424617ae7",
			Options: models.SuiObjectDataOptions{
				ShowContent:             true,
				ShowPreviousTransaction: true,
			},
		},
	)
	if err != nil {
		return err
	}

	active_jwks := objdata.Content.SuiMoveObject.Fields["value"].(map[string]any)["fields"].(map[string]any)["active_jwks"].([]any)

	// w := []map[string]any{}
	for _, v := range active_jwks {
		jwks := v.(map[string]any)
		// _ = jwks
		jwskKey, err := NewJwksKey(jwks)
		if err != nil {
			return err
		}
		_ = jwskKey
		// jwksDb.Add(jwks)
		// w = append(w, jwks.(map[string]any))
	}
	return nil
	// fmt.Println(active_jwks)
}
