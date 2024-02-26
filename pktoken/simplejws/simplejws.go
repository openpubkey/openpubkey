package simplejws

import (
	"encoding/json"
	"fmt"

	"github.com/openpubkey/openpubkey/util"
)

type Jws struct {
	Payload    string      `json:"payload"`    // Base64 encoded
	Signatures []Signature `json:"signatures"` // Base64 encoded
}
type Signature struct {
	Protected string                 `json:"protected"` // Base64 encoded
	Public    map[string]interface{} `json:"header,omitempty"`
	Signature string                 `json:"signature"` // Base64 encoded
}

func (s *Signature) GetTyp() (string, error) {
	decodedProtected, err := util.Base64DecodeForJWT([]byte(s.Protected))
	if err != nil {
		return "", err
	}
	type protectedTyp struct {
		Typ string `json:"typ"`
	}
	var ph protectedTyp
	err = json.Unmarshal(decodedProtected, &ph)
	if err != nil {
		return "", err
	}
	return ph.Typ, nil
}

func (j *Jws) GetToken(i int) ([]byte, error) {
	if i < len(j.Signatures) && i >= 0 {
		return []byte(j.Signatures[i].Protected + "." + j.Payload + "." + j.Signatures[i].Signature), nil
	} else {
		return nil, fmt.Errorf("no signature at index i (%d), len(signatures) (%d)", i, len(j.Signatures))
	}
}

func (j *Jws) GetTokenByTyp(typ string) ([]byte, error) {
	matchingTokens := []Signature{}
	for _, v := range j.Signatures {
		if typFound, err := v.GetTyp(); err != nil {
			return nil, err
		} else {
			// Both the JWS standard and the OIDC standard states that typ is case sensitive
			// so we treat it as case sensitive as well
			//
			// "The typ (type) header parameter is used to declare the type of the
			// signed content. The typ value is case sensitive."
			// https://openid.net/specs/draft-jones-json-web-signature-04.html#ReservedHeaderParameterName
			//
			// "The "typ" (type) Header Parameter is used by JWS applications to
			// declare the media type [IANA.MediaTypes] of this complete JWS.
			// [..] Per RFC 2045 [RFC2045], all media type values, subtype values, and
			// parameter names are case insensitive. However, parameter values are case
			// sensitive unless otherwise specified for the specific parameter."
			// https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.9
			if typFound == typ {
				matchingTokens = append(matchingTokens, v)
			}
		}
	}
	if len(matchingTokens) > 1 {
		// Currently we only have one token per token typ. We can change this later
		// for COS tokens. This check prevents hidden tokens, where one token of
		// the same typ hides another token of the same typ.
		return nil, fmt.Errorf("more than one token found, all current token typs are unique")
	} else if len(matchingTokens) == 0 {
		// if typ not found return nil
		return nil, nil
	} else {
		return []byte(matchingTokens[0].Protected + "." + j.Payload + "." + matchingTokens[0].Signature), nil
	}
}
