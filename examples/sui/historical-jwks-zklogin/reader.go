package reader

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/block-vision/sui-go-sdk/models"
	"github.com/block-vision/sui-go-sdk/sui"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/openpubkey/openpubkey/ajwks"
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

func NewJwksKey(jwksMap map[string]any, timestampMS uint64) (*ajwks.JwksKey, error) {

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

	// fmt.Println(epoch, jwkObj, jwkId, iss, kid, key)
	return &ajwks.JwksKey{
		Issuer:      iss,
		KeyId:       kid,
		Epoch:       epoch,
		TimestampMS: timestampMS,
		JwkKey:      key,
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

type SuiJwksArchive struct {
	rpcUrl    string
	client    sui.ISuiAPI
	jwksObjId string // This is the object ID of JWKS objects
}

func NewSuiJwksArchive(rpcUrl string) *SuiJwksArchive {
	return &SuiJwksArchive{
		rpcUrl:    rpcUrl,
		client:    sui.NewSuiClient(rpcUrl),
		jwksObjId: "0xcfecb053c69314e75f36561910f3535dd466b6e2e3593708f370e80424617ae7",
	}
}

func (s *SuiJwksArchive) GetLatestJwks(ctx context.Context) (map[string][]*ajwks.JwksKey, error) {
	objdata, err := s.client.SuiGetObject(ctx,
		models.SuiGetObjectRequest{
			ObjectId: s.jwksObjId,
			Options: models.SuiObjectDataOptions{
				ShowContent:             true,
				ShowPreviousTransaction: true,
				ShowBcs:                 true,
			},
		},
	)
	if err != nil {
		return nil, err
	}

	active_jwks := objdata.Content.SuiMoveObject.Fields["value"].(map[string]any)["fields"].(map[string]any)["active_jwks"].([]any)
	jwksIss := map[string][]*ajwks.JwksKey{}
	for _, v := range active_jwks {
		jwks := v.(map[string]any)
		jwskKey, err := NewJwksKey(jwks, 0)
		if err != nil {
			return nil, err
		}
		if jwksIss[jwskKey.Issuer] == nil {
			jwksIss[jwskKey.Issuer] = []*ajwks.JwksKey{}
		}
		jwksIss[jwskKey.Issuer] = append(jwksIss[jwskKey.Issuer], jwskKey)
	}
	return jwksIss, nil
}

func (s *SuiJwksArchive) GetPastJwks(ctx context.Context, depth int) (map[string]*[]ajwks.JwksSave, error) {
	jwksIss := map[string]*[]ajwks.JwksSave{}

	objdata, err := s.client.SuiGetObject(ctx,
		models.SuiGetObjectRequest{
			ObjectId: s.jwksObjId,
			Options: models.SuiObjectDataOptions{
				ShowContent:             true,
				ShowPreviousTransaction: true,
			},
		},
	)
	if err != nil {
		return nil, err
	}

	prevTxnDigest := objdata.PreviousTransaction

	for i := 0; i < depth; i++ {
		prevobjdata, err := s.client.SuiGetTransactionBlock(ctx,
			models.SuiGetTransactionBlockRequest{
				Digest: prevTxnDigest,
				Options: models.SuiTransactionBlockOptions{
					ShowObjectChanges: true,
				},
			},
		)
		if err != nil {
			return nil, err
		}

		timestampMS, err := strconv.ParseUint(prevobjdata.TimestampMs, 10, 64)
		if err != nil {
			return nil, err
		}

		prevTxnDigestFound := false

		for _, change := range prevobjdata.ObjectChanges {
			if change.ObjectId == s.jwksObjId { // Filter out changes which aren't changes to the JWKS object
				pastObjId := change.ObjectId

				version, err := strconv.ParseUint(change.PreviousVersion, 10, 64)
				if err != nil {
					if change.PreviousVersion == "" {
						break
					}
					return nil, err
				}

				prevObj, err := s.client.SuiTryGetPastObject(ctx, models.SuiTryGetPastObjectRequest{
					ObjectId: pastObjId,
					Version:  version,
					Options: models.SuiObjectDataOptions{
						ShowContent:             true,
						ShowPreviousTransaction: true,
					},
				})
				if err != nil {
					return nil, err
				}
				if prevObj.Status != "VersionFound" {
					return nil, fmt.Errorf("unexpected status when fetching prevObj from sui, expected (VersionFound) got (%s)", prevObj.Status)
				}
				if prevTxnDigestFound {
					return nil, fmt.Errorf("Expecting only one prevTxn")
				}
				prevTxnDigestFound = true
				prevTxnDigest = prevObj.Details.(map[string]any)["previousTransaction"].(string)

				saves := map[string]*ajwks.JwksSave{}

				activeJwks := prevObj.Details.(map[string]any)["content"].(map[string]any)["fields"].(map[string]any)["value"].(map[string]any)["fields"].(map[string]any)["active_jwks"].([]any)
				for _, jkws := range activeJwks {

					jwks := jkws.(map[string]any)
					jwskKey, err := NewJwksKey(jwks, timestampMS)
					if err != nil {
						return nil, err
					}

					if k, ok := saves[jwskKey.Issuer]; !ok {
						saves[jwskKey.Issuer] = &ajwks.JwksSave{
							Iss:         jwskKey.Issuer,
							Epoch:       []string{jwskKey.Epoch},
							TimestampMS: jwskKey.TimestampMS,
							JwkKeys:     []*ajwks.JwksKey{jwskKey},
						}
					} else {
						if saves[jwskKey.Issuer].Iss != jwskKey.Issuer || saves[jwskKey.Issuer].TimestampMS != jwskKey.TimestampMS {
							return nil, fmt.Errorf("data in save doesn't match like it should match")
						}
						k.Epoch = append(k.Epoch, jwskKey.Epoch)
						k.JwkKeys = append(k.JwkKeys, jwskKey)
					}
				}

				for iss, save := range saves {
					if k, ok := jwksIss[iss]; !ok {
						jwksIss[iss] = &[]ajwks.JwksSave{*save}
					} else {
						*k = append(*k, *save)
					}
				}
			}
		}
	}
	return jwksIss, nil
}
