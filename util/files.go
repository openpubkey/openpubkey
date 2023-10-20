package util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func WriteCertFile(fpath string, cert []byte) error {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	return os.WriteFile(fpath, pemBytes, 0600)
}

func WritePKFile(fpath string, pk *ecdsa.PublicKey) error {
	x509Encoded, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509Encoded})

	return os.WriteFile(fpath, pemBytes, 0600)
}

func SKToX509Bytes(sk *ecdsa.PrivateKey) ([]byte, error) {
	x509Encoded, err := x509.MarshalECPrivateKey(sk)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded}), nil

}

func WriteSKFile(fpath string, sk *ecdsa.PrivateKey) error {
	pemBytes, err := SKToX509Bytes(sk)
	if err != nil {
		return err
	}

	return os.WriteFile(fpath, pemBytes, 0600)
}

func ReadCertFile(fpath string) (*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(fpath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemBytes)
	return x509.ParseCertificate(block.Bytes)
}

func SecretKeyFromBytes(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	return x509.ParseECPrivateKey(block.Bytes)
}

func X509PublicKeyBytesFromJWK(upkjwk jwk.Key) ([]byte, error) {
	var rawkey interface{}
	if err := upkjwk.Raw(&rawkey); err != nil {
		return nil, err
	}
	pupkPKTCom := rawkey.(*ecdsa.PublicKey)

	return x509.MarshalPKIXPublicKey(pupkPKTCom)
}

func ReadPKFile(fpath string) (*ecdsa.PublicKey, error) {
	pemBytes, err := os.ReadFile(fpath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	pkAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pk := pkAny.(*ecdsa.PublicKey)
	return pk, nil
}

func ReadSKFile(fpath string) (*ecdsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(fpath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(pemBytes))
	return x509.ParseECPrivateKey(block.Bytes)
}

func GenKeyPair(alg jwa.KeyAlgorithm) (crypto.Signer, error) {
	switch alg {
	case jwa.ES256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case jwa.RS256: // RSASSA-PKCS-v1.5 using SHA-256
		return rsa.GenerateKey(rand.Reader, 2048)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", alg.String())
	}
}

func B64SHA3_256(msg []byte) []byte {
	h := crypto.SHA3_256.New()
	h.Write(msg)
	image := h.Sum(nil)
	return Base64EncodeForJWT(image)
}
