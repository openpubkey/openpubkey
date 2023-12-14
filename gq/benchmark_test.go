package gq

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
)

var result error
var boolResult bool

type testTuple struct {
	rsaPublicKey *rsa.PublicKey
	token        []byte
}

func BenchmarkSigning(b *testing.B) {
	// Generate test matrix
	matrix, err := generateTestMatrix(b.N)
	if err != nil {
		b.Fatal(err)
	}

	// Reset the benchmark timer to exclude setup time
	b.ResetTimer()

	var signerVerifier SignerVerifier
	for i := 0; i < b.N; i++ {
		signerVerifier, err = NewSignerVerifier(matrix[i].rsaPublicKey, 256)
		if err != nil {
			b.Fatal(err)
		}
		_, err = signerVerifier.SignJWT(matrix[i].token)
	}

	// Avoid compiler optimisations eliminating the function under test and artificially lowering the run time of the benchmark
	// ref: https://dave.cheney.net/2013/06/30/how-to-write-benchmarks-in-go
	result = err
}

func BenchmarkVerifying(b *testing.B) {
	// Generate test matrix
	matrix, err := generateTestMatrix(b.N)
	if err != nil {
		b.Fatal(err)
	}

	// Generate signatures using matrix
	gqSignedTokens := [][]byte{}
	for i := 0; i < b.N; i++ {
		signerVerifier, err := NewSignerVerifier(matrix[i].rsaPublicKey, 256)
		if err != nil {
			b.Fatal(err)
		}
		sig, err := signerVerifier.SignJWT(matrix[i].token)
		if err != nil {
			b.Fatal(err)
		}

		gqSignedTokens = append(gqSignedTokens, sig)
	}

	// Reset the benchmark timer to exclude setup time
	b.ResetTimer()

	var ok bool
	for i := 0; i < b.N; i++ {
		signerVerifier, err := NewSignerVerifier(matrix[i].rsaPublicKey, 256)
		if err != nil {
			b.Fatal(err)
		}
		ok = signerVerifier.VerifyJWT(gqSignedTokens[i])
		if !ok {
			b.Fatal(fmt.Errorf("Failed to verify signature!"))
		}
	}

	// Avoid compiler optimisations eliminating the function under test and artificially lowering the run time of the benchmark
	// ref: https://dave.cheney.net/2013/06/30/how-to-write-benchmarks-in-go
	boolResult = ok
}

func generateTestMatrix(n int) ([]testTuple, error) {
	tests := []testTuple{}
	for i := 0; i < n; i++ {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}

		jwt, err := createOIDCToken(key, "very_fake_audience_claim")
		if err != nil {
			return nil, err
		}

		tests = append(tests, testTuple{rsaPublicKey: &key.PublicKey, token: jwt})
	}

	return tests, nil
}
