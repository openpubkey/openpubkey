package gq

import (
	"fmt"
	"math/big"
	"slices"

	"github.com/bastionzero/openpubkey/util"
)

func (sv *signerVerifier) Verify(proof []byte, signingPayload []byte) bool {
	n, v, t := sv.n, sv.v, sv.t
	nBytes, vBytes := sv.nBytes, sv.vBytes

	paddedPayload := encodePKCS1v15(nBytes, signingPayload)
	G := new(big.Int).SetBytes(paddedPayload)

	R, S, err := sv.decodeProof(proof)
	if err != nil {
		return false
	}

	M := signingPayload

	Rs := make([]*big.Int, t)
	for i := 0; i < t; i++ {
		Rs[i] = new(big.Int).SetBytes(R[i*vBytes : (i+1)*vBytes])
	}

	Ss := make([]*big.Int, t)
	for i := 0; i < t; i++ {
		s_i := new(big.Int).SetBytes(S[i*nBytes : (i+1)*nBytes])
		if s_i.Cmp(big.NewInt(0)) == 0 || s_i.Cmp(n) != -1 {
			return false
		}
		Ss[i] = s_i
	}

	var W []byte
	for i := 0; i < t; i++ {
		l := new(big.Int).Exp(Ss[i], v, n)
		r := new(big.Int).Exp(G, Rs[i], n)
		W_i := new(big.Int).Mul(l, r)
		W_i.Mod(W_i, n)
		b := make([]byte, nBytes)
		W = append(W, W_i.FillBytes(b)...)
	}

	Rstar := hash(t*vBytes, W, M)

	return slices.Equal(R, Rstar)
}

func (sv *signerVerifier) decodeProof(s []byte) (R, S []byte, err error) {
	bin, err := util.Base64Decode(s)
	if err != nil {
		return nil, nil, err
	}

	rSize := sv.vBytes * sv.t
	sSize := sv.nBytes * sv.t

	if len(bin) != rSize+sSize {
		return nil, nil, fmt.Errorf("not the correct size")
	}

	R = bin[:rSize]
	S = bin[rSize:]

	return R, S, nil
}
