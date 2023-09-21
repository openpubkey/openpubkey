package gq

import (
	"crypto/rand"
	"math/big"

	"github.com/bastionzero/openpubkey/util"
)

// Sign creates a GQ1 signature over the given message with the given GQ1 private number.
//
// Comments throughout refer to stages as specified in the ISO/IEC 14888-2 standard.
func (sv *signerVerifier) Sign(private []byte, message []byte) []byte {
	n, v, t := sv.n, sv.v, sv.t
	nBytes, vBytes := sv.nBytes, sv.vBytes

	Q := new(big.Int).SetBytes(private)
	M := message

	// Stage 1 - select t numbers, each consisting of nBytes random bytes
	r := randomNumbers(t, nBytes)

	// Stage 2 - calculate test number W
	// for i from 1 to t, compute W_i <- r_i^v mod n
	// combine to form W
	var W []byte
	for i := 0; i < t; i++ {
		W_i := new(big.Int).Exp(r[i], v, n)
		b := make([]byte, nBytes)
		W = append(W, W_i.FillBytes(b)...)
	}

	// Stage 3 - calculate question number R
	// hash W and M and take first t*vBytes bytes as R
	R := hash(t*vBytes, W, M)

	// split R into t numbers each consisting of vBytes bytes
	Rs := make([]*big.Int, t)
	for i := 0; i < t; i++ {
		Rs[i] = new(big.Int).SetBytes(R[i*vBytes : (i+1)*vBytes])
	}

	// Stage 4 - calculate witness number S
	// for i from 1 to t, compute S_i <- r_i * Q^{R_i} mod n
	// combine to form S
	var S []byte
	for i := 0; i < t; i++ {
		S_i := new(big.Int).Exp(Q, Rs[i], n)
		S_i.Mul(S_i, r[i])
		S_i.Mod(S_i, n)
		b := make([]byte, nBytes)
		S = append(S, S_i.FillBytes(b)...)
	}

	// proof is combination of R and S
	return encodeProof(R, S)
}

func (sv *signerVerifier) SignJWTIdentity(jwt []byte) ([]byte, error) {
	signingPayload, signature, err := util.SplitDecodeJWT(jwt)
	if err != nil {
		return nil, err
	}

	// GQ1 private number (Q) is inverse of RSA signature mod n
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
