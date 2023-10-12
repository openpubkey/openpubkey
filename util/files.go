package util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func WriteCertFile(fpath string, cert []byte) error {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	err := os.WriteFile(fpath, pemBytes, 0600)
	if err != nil {
		return err
	}
	return nil
}

func WritePKFile(fpath string, pk *ecdsa.PublicKey) error {
	x509Encoded, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509Encoded})

	err = os.WriteFile(fpath, pemBytes, 0600)
	if err != nil {
		return err
	}
	return nil
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

	err = os.WriteFile(fpath, pemBytes, 0600)
	if err != nil {
		return err
	}
	return nil
}

func ReadCertFile(fpath string) (*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(fpath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
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

	x509PublicKeyBytes, err := x509.MarshalPKIXPublicKey(pupkPKTCom)
	if err != nil {
		return nil, err
	} else {
		return x509PublicKeyBytes, nil
	}
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
	sk, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return sk, nil
}

func GenKeyPair(alg string) (*ecdsa.PrivateKey, error) {
	if alg == "ES256" {
		pksk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		} else {
			return pksk, nil
		}
	} else {
		return nil, fmt.Errorf("Algorithm, %s, not supported", alg)
	}
}

func B64SHA3_256(msg []byte) []byte {
	h := crypto.SHA3_256.New()
	h.Write(msg)
	image := h.Sum(nil)
	return []byte(base64.RawStdEncoding.EncodeToString(image))
}

func GetRandString(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), err
}
