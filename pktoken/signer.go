package pktoken

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"openpubkey/util"
	"os"
	"path"

	_ "golang.org/x/crypto/sha3" // Needed to loads SHA3, throws "crypto: requested hash function #11 is unavailable if this import is missing

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// variable names with a postfix of Com denotes compact representation

type Signer struct {
	Pksk    *ecdsa.PrivateKey
	alg     string
	rz      string
	cfgPath string
	PktCom  []byte
}

func NewSigner(cfgPath string, alg string) *Signer {
	pksk, err := util.GenKeyPair(alg)
	if err != nil {
		panic(err)
	}
	rz := GenRZ()

	us := Signer{
		Pksk:    pksk,
		alg:     alg,
		rz:      rz,
		cfgPath: cfgPath,
	}

	return &us
}

func LoadSigner(cfgPath string, pktCom []byte, uSkBytes []byte, alg string) (*Signer, error) {
	pksk, err := util.SecretKeyFromBytes(uSkBytes)
	if err != nil {
		return nil, err
	} else {
		return &Signer{
			Pksk:    pksk,
			alg:     alg,
			PktCom:  pktCom,
			cfgPath: cfgPath,
		}, nil
	}
}

func LoadFromFile(cfgPath string, alg string) (*Signer, error) {

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

	return LoadSigner(cfgPath, pktCom, uSkBytes, alg)
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
	return ComputeNonce(u.alg, u.rz, upk)
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
	opPH, opPayload, opSig, err := jws.SplitCompact(idtCom)
	if err != nil {
		return nil, err
	}

	cicsigb64, err := s.CicSignature(opPayload)
	if err != nil {
		return nil, err
	}

	cicPH, cicPayload, cicSig, err := jws.SplitCompact(cicsigb64)
	if !bytes.Equal(opPayload, cicPayload) {
		return nil, fmt.Errorf("Both signatures must share the same payload, opPayload=%s,  cicPayload=%s", opPayload, cicPayload)
	}
	payload := opPayload

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

func (s *Signer) CicSignature(payload []byte) ([]byte, error) {
	jwkPK := s.GetPubKey()
	hdrs := jws.NewHeaders()
	hdrs.Set(`upk`, jwkPK)
	hdrs.Set(`rz`, s.rz)
	hdrs.Set(`alg`, s.alg)

	decodePayload, err := base64.RawStdEncoding.DecodeString(string(payload))
	if err != nil {
		return nil, err
	}

	sig, err := jws.Sign(decodePayload, jws.WithKey(jwa.ES256, s.Pksk, jws.WithProtectedHeaders(hdrs)))

	// Returns Compact representation of the signature "<payload>.<protected header>.<signatgure>"
	return sig, err
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

func ComputeNonce(alg string, rz string, upk jwk.Key) string {
	m := map[string]interface{}{
		"alg": alg,
		"rz":  rz,
		"upk": upk,
	}
	buf, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return string(util.B64SHA3_256(buf))
}
