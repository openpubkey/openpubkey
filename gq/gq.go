package gq

import (
	"crypto/rsa"
	"io"
	"math/big"

	"golang.org/x/crypto/sha3"
)

type Signer interface {
	Sign(private []byte, message []byte) []byte
	SignJWTIdentity(jwt []byte) ([]byte, error)
}

type Verifier interface {
	Verify(proof []byte, identity []byte) bool
}

type SignerVerifier interface {
	Signer
	Verifier
}

type signerVerifier struct {
	n      *big.Int
	v      *big.Int
	nBytes int
	vBytes int
	t      int

	rng io.Reader
}

func NewSignerVerifier(publicKey *rsa.PublicKey, securityParameter int, rng io.Reader) SignerVerifier {
	n, v, nBytes, vBytes := parsePublicKey(publicKey)
	t := securityParameter / (vBytes * 8)

	return &signerVerifier{n, v, nBytes, vBytes, t, rng}
}

func parsePublicKey(publicKey *rsa.PublicKey) (n *big.Int, v *big.Int, nBytes int, vBytes int) {
	n, v = publicKey.N, big.NewInt(int64(publicKey.E))
	nLen := n.BitLen()
	vLen := v.BitLen() - 1
	nBytes = bytesForBits(nLen)
	vBytes = bytesForBits(vLen)
	return
}

func bytesForBits(bits int) int {
	return (bits + 7) / 8
}

func hash(byteCount int, data ...[]byte) []byte {
	rng := sha3.NewShake256()
	for _, d := range data {
		rng.Write(d)
	}

	return randomBytes(rng, byteCount)
}

func randomBytes(rng io.Reader, byteCount int) []byte {
	bytes := make([]byte, byteCount)

	_, err := io.ReadFull(rng, bytes)
	if err != nil {
		panic(err)
	}

	return bytes
}
