package cosigner

import (
	"crypto"
	"encoding/json"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/pktoken"
)

type Cosigner struct {
	Alg    jwa.KeyAlgorithm
	Signer crypto.Signer
}

func (c *Cosigner) Cosign(pkt *pktoken.PKToken, cosClaims pktoken.CosignerClaims) ([]byte, error) {
	jsonBytes, err := json.Marshal(cosClaims)
	if err != nil {
		return nil, err
	}
	var headers map[string]any
	if err := json.Unmarshal(jsonBytes, &headers); err != nil {
		return nil, err
	}
	return pkt.SignToken(c.Signer, c.Alg, headers)
}
