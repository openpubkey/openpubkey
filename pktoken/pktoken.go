package pktoken

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

const SigTypeHeader = "sig_type"
const SigTypeOIDC = "oidc"
const SigTypeGQ = "oidc_gq"
const SigTypeCIC = "cic"
const SigTypeCos = "cos"

type JWS struct {
	Payload    string        `json:"payload"`
	Signatures []JWSignature `json:"signatures"`
}

type JWSignature struct {
	Protected string         `json:"protected"`
	Public    map[string]any `json:"header"`
	Signature string         `json:"signature"`
}

type PKToken struct {
	Payload []byte
	OpPH    []byte
	OpSig   []byte
	OpSigGQ bool
	CicPH   []byte
	CicSig  []byte
	CosPH   []byte
	CosSig  []byte
}

func FromCompact(pktCom []byte) (*PKToken, error) {
	splitCom := bytes.Split(pktCom, []byte(":"))
	if len(splitCom) == 5 {
		return &PKToken{
			Payload: splitCom[0],
			OpPH:    splitCom[1],
			OpSig:   splitCom[2],
			CicPH:   splitCom[3],
			CicSig:  splitCom[4],
			CosPH:   nil,
			CosSig:  nil,
		}, nil
	} else if len(splitCom) == 7 {
		return &PKToken{
			Payload: splitCom[0],
			OpPH:    splitCom[1],
			OpSig:   splitCom[2],
			CicPH:   splitCom[3],
			CicSig:  splitCom[4],
			CosPH:   splitCom[5],
			CosSig:  splitCom[6],
		}, nil
	} else {
		return nil, fmt.Errorf("A valid PK Token should have exactly two or three (protected header, signature pairs), but has %d signatures", len(splitCom))
	}
}

func (p *PKToken) ToCompact() []byte {
	if p.Payload == nil {
		panic(fmt.Errorf("Payload can not be nil"))
	}

	var buf bytes.Buffer
	buf.WriteString(string(p.Payload))
	buf.WriteByte(':')
	buf.WriteString(string(p.OpPH))
	buf.WriteByte(':')
	buf.WriteString(string(p.OpSig))
	buf.WriteByte(':')
	buf.WriteString(string(p.CicPH))
	buf.WriteByte(':')
	buf.WriteString(string(p.CicSig))

	if p.CosPH != nil {
		buf.WriteByte(':')
		buf.WriteString(string(p.CosPH))
		buf.WriteByte(':')
		buf.WriteString(string(p.CosSig))
	}

	pktCom := buf.Bytes()
	return pktCom
}

func FromJWS(jws *JWS) *PKToken {
	var cic, op, cos JWSignature

	gq := false
	hasCos := false
	for _, sig := range jws.Signatures {
		switch sig.Public[SigTypeHeader] {
		case SigTypeOIDC:
			op = sig
		case SigTypeGQ:
			op = sig
			gq = true
		case SigTypeCIC:
			cic = sig
		case SigTypeCos:
			cos = sig
			hasCos = true
		}
	}

	tok := &PKToken{
		Payload: []byte(jws.Payload),
		OpPH:    []byte(op.Protected),
		OpSig:   []byte(op.Signature),
		OpSigGQ: gq,
		CicPH:   []byte(cic.Protected),
		CicSig:  []byte(cic.Signature),
	}

	if hasCos {
		tok.CosPH = []byte(cos.Protected)
		tok.CosSig = []byte(cos.Signature)
	}

	return tok
}

func (p *PKToken) ToJWS() *JWS {
	var opSignType string
	if p.OpSigGQ {
		opSignType = SigTypeGQ
	} else {
		opSignType = SigTypeOIDC
	}

	opHeaders := map[string]any{
		SigTypeHeader: opSignType,
	}

	signatures := []JWSignature{
		{
			Public:    map[string]any{SigTypeHeader: SigTypeCIC},
			Protected: string(p.CicPH),
			Signature: string(p.CicSig),
		},
		{
			Public:    opHeaders,
			Protected: string(p.OpPH),
			Signature: string(p.OpSig),
		},
	}

	if p.CosPH != nil {
		signatures = append(signatures, JWSignature{
			Public:    map[string]any{SigTypeHeader: SigTypeCos},
			Protected: string(p.CosPH),
			Signature: string(p.CosSig),
		})
	}

	return &JWS{
		Payload:    string(p.Payload),
		Signatures: signatures,
	}
}

func FromJSON(in []byte) (*PKToken, error) {
	jws := new(JWS)
	err := json.Unmarshal(in, jws)
	if err != nil {
		return nil, err
	}

	return FromJWS(jws), nil
}

func (p *PKToken) ToJSON() ([]byte, error) {
	jws := p.ToJWS()
	jwsJSON, err := json.Marshal(jws)
	if err != nil {
		return nil, err
	}
	return jwsJSON, nil
}

func (p *PKToken) OpJWSCompact() []byte {
	if p.Payload == nil {
		panic(fmt.Errorf("Payload can not be nil"))
	}

	var buf bytes.Buffer
	buf.WriteString(string(p.OpPH))
	buf.WriteByte('.')
	buf.WriteString(string(p.Payload))
	buf.WriteByte('.')
	buf.WriteString(string(p.OpSig))

	jwsCom := buf.Bytes()
	return jwsCom
}

func (p *PKToken) CicJWSCompact() []byte {
	if p.Payload == nil {
		panic(fmt.Errorf("Payload can not be nil"))
	}

	var buf bytes.Buffer
	buf.WriteString(string(p.CicPH))
	buf.WriteByte('.')
	buf.WriteString(string(p.Payload))
	buf.WriteByte('.')
	buf.WriteString(string(p.CicSig))

	jwsCom := buf.Bytes()
	return jwsCom
}

func (p *PKToken) CosJWSCompact() []byte {
	if p.Payload == nil {
		panic(fmt.Errorf("Payload can not be nil"))
	}

	var buf bytes.Buffer
	buf.WriteString(string(p.CosPH))
	buf.WriteByte('.')
	buf.WriteString(string(p.Payload))
	buf.WriteByte('.')
	buf.WriteString(string(p.CosSig))

	jwsCom := buf.Bytes()
	return jwsCom
}

func (p *PKToken) GetNonce() ([]byte, error) {
	decodePayload, err := base64.RawStdEncoding.DecodeString(string(p.Payload))
	if err != nil {
		return nil, err
	}

	var payMap map[string]json.RawMessage
	err = json.Unmarshal(decodePayload, &payMap)
	if err != nil {
		return nil, err
	}

	var nonce string
	err = json.Unmarshal(payMap["nonce"], &nonce)
	if err != nil {
		return nil, err
	}

	return []byte(nonce), nil
}

func (p *PKToken) GetClaims() ([]byte, []byte, []byte, error) {
	decodePayload, err := base64.RawStdEncoding.DecodeString(string(p.Payload))
	if err != nil {
		return nil, nil, nil, err
	}

	var payMap map[string]interface{}
	err = json.Unmarshal(decodePayload, &payMap)
	if err != nil {
		return nil, nil, nil, err
	}

	iss := payMap["iss"].(string)
	aud := payMap["aud"].(string)
	email := payMap["email"].(string)

	return []byte(iss), []byte(aud), []byte(email), nil
}

func (p *PKToken) GetCicValues() (jwa.KeyAlgorithm, string, jwk.Key, error) {
	decodedCicPH, err := base64.RawStdEncoding.DecodeString(string(p.CicPH))
	if err != nil {
		return nil, "", nil, err
	}

	var hds map[string]interface{}
	json.Unmarshal(decodedCicPH, &hds)

	alg, _ := hds["alg"]
	rz, _ := hds["rz"]
	upk, _ := hds["upk"]

	algJwk := jwa.KeyAlgorithmFrom(alg)
	upkBytes, err := json.Marshal(upk)
	if err != nil {
		return nil, "", nil, err
	}

	upkjwk, err := jwk.ParseKey(upkBytes)
	if err != nil {
		return nil, "", nil, err
	}

	return algJwk, rz.(string), upkjwk, nil
}

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
	decodedCosPH, err := base64.RawStdEncoding.DecodeString(string(p.CosPH))
	if err != nil {
		return nil, err
	}

	var hds *CosPHeader
	json.Unmarshal(decodedCosPH, &hds)

	return hds, nil
}

// func (p *PKToken) GetPublicKey() ([]byte error){
// 	p.GetCicValues()
// }

func (p *PKToken) VerifyCicSig() error {
	cicJwsCom := p.CicJWSCompact()

	alg, _, upk, err := p.GetCicValues()
	if err != nil {
		return err
	}

	_, err = jws.Verify(cicJwsCom, jws.WithKey(alg, upk))
	if err != nil {
		return err
	}

	// Verified
	return nil
}

func (p *PKToken) Verify(msg string, sig []byte) error {
	jwsSig, err := jws.Parse(sig)
	if err != nil {
		return err
	}

	if msg != string(jwsSig.Payload()) {
		return fmt.Errorf("Message does not match signed message")
	}

	alg, _, upk, err := p.GetCicValues()
	if err != nil {
		return err
	}

	_, err = jws.Verify(sig, jws.WithKey(alg, upk))
	if err != nil {
		return err
	}

	// verified
	return nil
}
