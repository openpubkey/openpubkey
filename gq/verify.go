package gq

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/util"
)

// Verify verifies a GQ1 signature over a message, using the public identity of the signer.
//
// Comments throughout refer to stages as specified in the ISO/IEC 14888-2 standard.
func (sv *signerVerifier) Verify(proof []byte, identity []byte, message []byte) bool {
	n, v, t := modAsInt(sv.n), sv.v, sv.t
	nBytes, vBytes := sv.nBytes, sv.vBytes

	M := message

	// Stage 0 - reject proof if it's the wrong size based on t
	R, S, err := sv.decodeProof(proof)
	if err != nil {
		return false
	}

	// Stage 1 - create public number G
	// currently this hardcoded to use PKCS#1 v1.5 padding as the format mechanism
	paddedIdentity := encodePKCS1v15(nBytes, identity)
	G := new(big.Int).SetBytes(paddedIdentity)

	// Stage 2 - parse signature numbers and recalculate test number W*
	// split R into t strings, each consisting of vBytes bytes
	Rs := make([]*big.Int, t)
	for i := 0; i < t; i++ {
		Rs[i] = new(big.Int).SetBytes(R[i*vBytes : (i+1)*vBytes])
	}

	// split S into t strings, each consisting of nBytes bytes
	Ss := make([]*big.Int, t)
	for i := 0; i < t; i++ {
		s_i := new(big.Int).SetBytes(S[i*nBytes : (i+1)*nBytes])
		// reject if S_i = 0 or >= n
		if s_i.Cmp(big.NewInt(0)) == 0 || s_i.Cmp(n) != -1 {
			return false
		}
		Ss[i] = s_i
	}

	// recalculate test number W*
	// for i from 1 to t, compute W*_i <- S_i^v * G^{R_i} mod n
	// combine to form W*

	var Wstar []byte
	for i := 0; i < t; i++ {
		l := new(big.Int).Exp(Ss[i], v, n)
		r := new(big.Int).Exp(G, Rs[i], n)
		Wstar_i := new(big.Int).Mul(l, r)
		Wstar_i.Mod(Wstar_i, n)
		b := make([]byte, nBytes)
		Wstar = append(Wstar, Wstar_i.FillBytes(b)...)
	}

	// Stage 3 - recalculate question number R*
	// hash W* and M and take first t*vBytes bytes as R*
	Rstar, err := hash(t*vBytes, Wstar, M)
	if err != nil {
		// TODO: this can only happen if there's some error reading /dev/urandom or something
		// so should we return the proper error?
		return false
	}

	// Stage 4 - accept or reject depending on whether R and R* are identical
	return bytes.Equal(R, Rstar)
}

func (sv *signerVerifier) VerifyJWT(jwt []byte) bool {
	origHeaders, err := OriginalJWTHeaders(jwt)
	if err != nil {
		return false
	}

	_, payload, signature, err := jws.SplitCompact(jwt)
	if err != nil {
		return false
	}

	signingPayload := util.JoinJWTSegments(origHeaders, payload)

	return sv.Verify(signature, signingPayload, signingPayload)
}

func (sv *signerVerifier) decodeProof(s []byte) (R, S []byte, err error) {
	bin, err := util.Base64DecodeForJWT(s)
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
