package gq

import (
	"crypto/rand"
	"encoding/json"
	"math/big"

	"filippo.io/bigmod"
	"github.com/awnumar/memguard"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/util"
)

// Sign creates a GQ1 signature over the given message with the given GQ1 private number.
//
// Comments throughout refer to stages as specified in the ISO/IEC 14888-2 standard.
func (sv *signerVerifier) Sign(private []byte, message []byte) ([]byte, error) {
	n, v, t := sv.n, sv.v, sv.t
	vBytes := sv.vBytes

	M := message
	Q, err := bigmod.NewNat().SetBytes(private, n)
	if err != nil {
		return nil, err
	}

	// Stage 1 - select t numbers, each consisting of nBytes random bytes.
	// In order to guarantee our operation is constant time, we deviate slightly
	// from the standard and directly select an integer less than n
	r, err := randomNumbers(t, sv.n)
	if err != nil {
		return nil, err
	}

	// Stage 2 - calculate test number W
	// for i from 1 to t, compute W_i <- r_i^v mod n
	// combine to form W
	var W []byte
	for i := 0; i < t; i++ {
		W_i := bigmod.NewNat().Exp(r[i], v.Bytes(), n)
		W = append(W, W_i.Bytes(n)...)
	}

	// Stage 3 - calculate question number R
	// hash W and M and take first t*vBytes bytes as R
	R, err := hash(t*vBytes, W, M)
	if err != nil {
		return nil, err
	}

	// split R into t numbers each consisting of vBytes bytes
	Rs := make([]*bigmod.Nat, t)
	for i := 0; i < t; i++ {
		Rs[i], err = new(bigmod.Nat).SetBytes(R[i*vBytes:(i+1)*vBytes], n)
		if err != nil {
			return nil, err
		}
	}

	// Stage 4 - calculate witness number S
	// for i from 1 to t, compute S_i <- r_i * Q^{R_i} mod n
	// combine to form S
	var S []byte
	for i := 0; i < t; i++ {
		S_i := bigmod.NewNat().Exp(Q, Rs[i].Bytes(n), n)
		S_i.Mul(r[i], n)
		S = append(S, S_i.Bytes(n)...)
	}

	// proof is combination of R and S
	return encodeProof(R, S), nil
}

func (sv *signerVerifier) SignJWT(jwt []byte) ([]byte, error) {
	origHeaders, payload, signature, err := jws.SplitCompact(jwt)
	if err != nil {
		return nil, err
	}

	signingPayload := util.JoinJWTSegments(origHeaders, payload)

	headers := jws.NewHeaders()
	err = headers.Set(jws.AlgorithmKey, GQ256)
	if err != nil {
		return nil, err
	}
	err = headers.Set(jws.TypeKey, "JWT")
	if err != nil {
		return nil, err
	}
	err = headers.Set(jws.KeyIDKey, string(origHeaders))
	if err != nil {
		return nil, err
	}

	headersJSON, err := json.Marshal(headers)
	if err != nil {
		return nil, err
	}

	headersEnc := util.Base64EncodeForJWT(headersJSON)

	// When jwt is parsed it's split into base64-encoded bytes, but
	// we need the raw signature to calculate mod inverse
	decodedSig, err := util.Base64DecodeForJWT(signature)
	if err != nil {
		return nil, err
	}

	// GQ1 private number (Q) is inverse of RSA signature mod n
	private, err := sv.modInverse(memguard.NewBufferFromBytes(decodedSig))
	if err != nil {
		return nil, err
	}

	defer private.Destroy()

	gqSig, err := sv.Sign(private.Bytes(), signingPayload)
	if err != nil {
		return nil, err
	}

	// Now make a new GQ-signed token
	gqToken := util.JoinJWTSegments(headersEnc, payload, gqSig)

	return gqToken, nil
}

// modInverse finds the modular multiplicative inverse of the value stored in b
//
// All operations invovling the secret value are performed either with constant-
// time methods or with blinding (if sv has a source of randomness)
func (sv *signerVerifier) modInverse(b *memguard.LockedBuffer) (*memguard.LockedBuffer, error) {
	x, err := bigmod.NewNat().SetBytes(b.Bytes(), sv.n)
	if err != nil {
		return nil, err
	}

	nInt := natAsInt(sv.n.Nat(), sv.n)
	var r *big.Int
	var rConstant, xr *bigmod.Nat

	// Apply RSA blinding to the ModInverse operation.
	// Translates the technique formerly used in the Go Standard Library before they
	// switched to bigmod in late 2022. Since bigmod does not yet support constant-time
	// ModInverse, we perform the blinding so that the value of the private key is not
	// detectable via side channel.
	// Ref: https://github.com/golang/go/blob/5f60f844beb0581a19cb425a3338d79d322a7db2/src/crypto/rsa/rsa.go#L567-L596
	//
	// For a secret value x, the idea is to find m = 1/x mod n by calculating
	// rm/r mod n ==> r/(xr) mod n, where r is a random value

	for {
		// draw r
		r, err = rand.Int(rand.Reader, nInt)
		if err != nil {
			return nil, err
		}

		// compute xr = x * r
		xr, err = intAsNat(r, sv.n)
		if err != nil {
			return nil, err
		}
		xr.Mul(x, sv.n)

		// check that xr has a multiplicative inverse mod n. It is exceedingly
		// rare but technically possible for it not to, in which case we need
		// to draw a new value for r
		xrInt := natAsInt(xr, sv.n)
		inverse := new(big.Int).ModInverse(xrInt, nInt)
		if inverse != nil {
			break
		}
	}

	// overwrite x with the blinded value
	x = xr

	// calculate m/r mod n
	m := natAsInt(x, sv.n).ModInverse(natAsInt(x, sv.n), nInt)
	mConstant, err := intAsNat(m, sv.n)
	if err != nil {
		return nil, err
	}

	// remove the blinding by multiplying m/r by r
	rConstant, err = intAsNat(r, sv.n)
	if err != nil {
		return nil, err
	}
	mConstant.Mul(rConstant, sv.n)

	mFinal := natAsInt(mConstant, sv.n)

	// need to allocate memory for fixed length slice using FillBytes
	ret := make([]byte, len(b.Bytes()))
	defer b.Destroy()

	return memguard.NewBufferFromBytes(mFinal.FillBytes(ret)), nil
}

func encodeProof(R, S []byte) []byte {
	var bin []byte

	bin = append(bin, R...)
	bin = append(bin, S...)

	return util.Base64EncodeForJWT(bin)
}

var randomNumbers = func(t int, n *bigmod.Modulus) ([]*bigmod.Nat, error) {
	nInt := modAsInt(n)
	ys := make([]*bigmod.Nat, t)

	for i := 0; i < t; i++ {
		r, err := rand.Int(rand.Reader, nInt)
		if err != nil {
			return nil, err
		}

		ys[i], err = intAsNat(r, n)
		if err != nil {
			return nil, err
		}
	}

	return ys, nil
}
