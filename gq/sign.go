package gq

import (
	"crypto/rand"
	"math/big"

	"github.com/bastionzero/openpubkey/util"
)

func (sv *signerVerifier) Sign(private []byte, message []byte) []byte {
	n, v, t := sv.n, sv.v, sv.t
	nBytes, vBytes := sv.nBytes, sv.vBytes

	Q := new(big.Int).SetBytes(private)

	M := message

	r := randomNumbers(t, nBytes)

	var W []byte
	for i := 0; i < t; i++ {
		W_i := new(big.Int).Exp(r[i], v, n)
		b := make([]byte, nBytes)
		W = append(W, W_i.FillBytes(b)...)
	}

	R := hash(t*vBytes, W, M)

	Rs := make([]*big.Int, t)
	for i := 0; i < t; i++ {
		Rs[i] = new(big.Int).SetBytes(R[i*vBytes : (i+1)*vBytes])
	}

	var S []byte
	for i := 0; i < t; i++ {
		S_i := new(big.Int).Exp(Q, Rs[i], n)
		S_i.Mul(S_i, r[i])
		S_i.Mod(S_i, n)
		b := make([]byte, nBytes)
		S = append(S, S_i.FillBytes(b)...)
	}

	return encodeProof(R, S)
}

func (sv *signerVerifier) SignJWTIdentity(jwt []byte) ([]byte, error) {
	signingPayload, signature, err := util.SplitDecodeJWTSignature(jwt)
	if err != nil {
		return nil, err
	}

	private := sv.modInverse(signature)

	proof := sv.Sign(private, signingPayload)
	return proof, nil
}

func (sv *signerVerifier) modInverse(b []byte) []byte {
	x := new(big.Int).SetBytes(b)
	x.ModInverse(x, sv.n)

	ret := make([]byte, len(b))
	return x.FillBytes(ret)
}

func encodeProof(R, S []byte) []byte {
	var bin []byte

	bin = append(bin, R...)
	bin = append(bin, S...)

	return util.Base64Encode(bin)
}

func randomNumbers(t int, nBytes int) []*big.Int {
	ys := make([]*big.Int, t)

	for i := 0; i < t; i++ {
		bytes := randomBytes(rand.Reader, nBytes)
		ys[i] = new(big.Int).SetBytes(bytes)
	}

	return ys
}
