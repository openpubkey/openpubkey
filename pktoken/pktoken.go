package pktoken

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

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
		panic(fmt.Errorf("HIIIIIIII"))
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

func (p *PKToken) AddCosSig(jwsCom []byte) error {

	cosPH, cosPayload, cosSig, err := jws.SplitCompact(jwsCom)
	if err != nil {
		return err
	}
	if !bytes.Equal(p.Payload, cosPayload) {
		return fmt.Errorf("Payload in the Cosigner JWS (%s) does not match the existing payload in the PK Token (%s).", p.Payload, cosPayload)
	}

	p.CosPH = cosPH
	p.CosSig = cosSig
	return nil
}

// TODO: Make this take a cosignerid and JWKS that we trust
func (p *PKToken) VerifyCosSig(cosPk jwk.Key, alg jwa.KeyAlgorithm) error {
	if p.CosPH == nil {
		return fmt.Errorf("Failed to verify Cosigner signature as Cosigner Protected header is nil.")
	}
	if p.CosSig == nil {
		return fmt.Errorf("Failed to verify Cosigner signature as the Cosigner Signature is nil.")
	}

	cosJwsCom := p.CosJWSCompact()
	_, err := jws.Verify(cosJwsCom, jws.WithKey(alg, cosPk))
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
