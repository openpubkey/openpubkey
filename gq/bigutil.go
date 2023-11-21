package gq

import (
	"math/big"

	"filippo.io/bigmod"
)

// leaks only the size of x
func modAsInt(x *bigmod.Modulus) *big.Int {
	return new(big.Int).SetBytes(x.Nat().Bytes(x))
}

// leaks only the size of x
func natAsInt(x *bigmod.Nat, m *bigmod.Modulus) *big.Int {
	return new(big.Int).SetBytes(x.Bytes(m))
}

// leaks only the size of x
func intAsNat(x *big.Int, m *bigmod.Modulus) (*bigmod.Nat, error) {
	return bigmod.NewNat().SetBytes(x.Bytes(), m)
}
