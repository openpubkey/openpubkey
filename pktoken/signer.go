package pktoken

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"

	_ "golang.org/x/crypto/sha3" // Needed to loads SHA3, throws "crypto: requested hash function #11 is unavailable if this import is missing

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"

	"github.com/bastionzero/openpubkey/util"
)

// Variable names with a postfix of "com" denotes that value is stored as a compact JWT representation (See RFC7519)
// https://datatracker.ietf.org/doc/html/rfc7519

type Signer struct {
	Pksk     *ecdsa.PrivateKey
	alg      string
	rz       string
	cfgPath  string
	GqSig    bool
	PktCom   []byte
	extraCIC map[string]any
}

func NewSigner(cfgPath string, alg string, gqSig bool, extraCIC map[string]any) *Signer {
	pksk, err := util.GenKeyPair(alg)
	if err != nil {
		panic(err)
	}
	rz := GenRZ()

	us := Signer{
		Pksk:     pksk,
		alg:      alg,
		rz:       rz,
		GqSig:    gqSig,
		cfgPath:  cfgPath,
		extraCIC: extraCIC,
	}

	return &us
}

func LoadSigner(cfgPath string, pktCom []byte, uSk *ecdsa.PrivateKey, alg string, gqSig bool, extraCIC map[string]any) *Signer {
	return &Signer{
		Pksk:     uSk,
		alg:      alg,
		PktCom:   pktCom,
		GqSig:    gqSig,
		cfgPath:  cfgPath,
		extraCIC: extraCIC,
	}
}

func LoadFromFile(cfgPath string, alg string, gqSig bool, extraCIC map[string]any) (*Signer, error) {

	fpPkT := path.Join(cfgPath, "pkt.pub")
	fpUsK := path.Join(cfgPath, "usk.sk")

	pktCom, err := os.ReadFile(fpPkT)
	if err != nil {
		return nil, err
	}

	uSkBytes, err := os.ReadFile(fpUsK)
	if err != nil {
		return nil, err
	}

	pksk, err := util.SecretKeyFromBytes(uSkBytes)
	if err != nil {
		return nil, err
	}

	return LoadSigner(cfgPath, pktCom, pksk, alg, gqSig, extraCIC), nil
}

func (u *Signer) WriteToFile(pktCom []byte) error {
	err := os.MkdirAll(u.cfgPath, os.ModePerm)
	if err != nil {
		return err
	}

	fpPkT := path.Join(u.cfgPath, "pkt.pub")
	fpUsK := path.Join(u.cfgPath, "usk.sk")

	if err != nil {
		return err
	}

	err = os.WriteFile(fpPkT, pktCom, 0600)
	if err != nil {
		return err
	}

	pksk := u.GetSK()
	err = util.WriteSKFile(fpUsK, pksk)
	if err != nil {
		return err
	}

	return nil
}

func (u *Signer) GetNonce() string {
	upk := u.GetPubKey()
	return ComputeNonce(u.alg, u.rz, upk, u.extraCIC)
}

func (u *Signer) GetSK() *ecdsa.PrivateKey {
	return u.Pksk
}

func (s *Signer) GetPubKey() jwk.Key {
	upk, err := jwk.PublicKeyOf(s.Pksk)
	if err != nil {
		panic(err)
	}
	return upk
}

func (s *Signer) CreatePkToken(idtCom []byte) (*PKToken, error) {
	opPH, payload, opSig, err := jws.SplitCompact(idtCom)
	if err != nil {
		return nil, err
	}

	cicSig, cicPH, err := s.CicSignature(payload)
	if err != nil {
		return nil, err
	}

	return &PKToken{
		Payload: payload,
		OpPH:    opPH,
		OpSig:   opSig,
		CicPH:   cicPH,
		CicSig:  cicSig,
		CosSig:  nil,
		CosPH:   nil,
	}, nil
}

func (s *Signer) CicSignature(payload []byte) ([]byte, []byte, error) {
	jwkPK := s.GetPubKey()
	hdrs := jws.NewHeaders()
	hdrs.Set(`upk`, jwkPK)
	hdrs.Set(`rz`, s.rz)
	hdrs.Set(`alg`, s.alg)
	for k, v := range s.extraCIC {
		hdrs.Set(k, v)
	}

	decodePayload, err := base64.RawStdEncoding.DecodeString(string(payload))
	if err != nil {
		return nil, nil, err
	}

	jwSig, err := jws.Sign(decodePayload, jws.WithKey(jwa.ES256, s.Pksk, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return nil, nil, err
	}

	ph, _, sig, err := jws.SplitCompact(jwSig)
	if err != nil {
		return nil, nil, err
	}

	return sig, ph, nil
}

func (s *Signer) Sign(payload []byte) ([]byte, error) {
	jwkPK := s.GetPubKey()
	hdrs := jws.NewHeaders()
	hdrs.Set(`jwk`, jwkPK)

	sig, err := jws.Sign(payload, jws.WithKey(jwa.ES256, s.Pksk, jws.WithProtectedHeaders(hdrs)))
	return sig, err
}

func (s *Signer) Verify(sigma []byte) error {
	_, err := jws.Verify(sigma, jws.WithKey(jwa.ES256, &s.Pksk.PublicKey))
	return err
}

func GenRZ() string {
	bits := 256
	rBytes := make([]byte, bits/8)
	n, err := rand.Read(rBytes)
	if err != nil {
		panic(err)
	}
	if n != bits/8 {
		panic(fmt.Errorf("Expected to receive 32 bytes of randomness, but got %d bytes instead!", n))
	}

	rz := hex.EncodeToString(rBytes)
	return rz
}

func ComputeNonce(alg string, rz string, upk jwk.Key, extraCIC map[string]any) string {
	m := map[string]interface{}{
		"alg": alg,
		"rz":  rz,
		"upk": upk,
	}
	for k, v := range extraCIC {
		m[k] = v
	}
	buf, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return string(util.B64SHA3_256(buf))
}
