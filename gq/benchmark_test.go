package gq_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/openpubkey/openpubkey/gq"
)

var result error
var boolResult bool

type testTuple struct {
	rsaPublicKey *rsa.PublicKey
	private      string
	message      string
}

func BenchmarkSigning(b *testing.B) {
	// Generate test matrix
	matrix, err := generateTestMatrix(b.N, 10, 10)
	if err != nil {
		b.Fatal(err)
	}

	fmt.Println("here")

	// Reset the benchmark timer to exclude setup time
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		signerVerifier := gq.NewSignerVerifier(matrix[i].rsaPublicKey, 256)
		_, err = signerVerifier.Sign([]byte(matrix[i].private), []byte(matrix[i].message))
	}

	// Avoid compiler optimisations eliminating the function under test and artificially lowering the run time of the benchmark
	// ref: https://dave.cheney.net/2013/06/30/how-to-write-benchmarks-in-go
	result = err
}

func BenchmarkVerifying(b *testing.B) {
	// Generate test matrix
	matrix, err := generateTestMatrix(b.N, 10, 10)
	if err != nil {
		b.Fatal(err)
	}

	// Generate signatures using matrix
	signatures := [][]byte{}
	for i := 0; i < b.N; i++ {
		signerVerifier := gq.NewSignerVerifier(matrix[i].rsaPublicKey, 256)
		sig, err := signerVerifier.Sign([]byte(matrix[i].private), []byte(matrix[i].message))
		if err != nil {
			b.Fatal(err)
		}

		signatures = append(signatures, sig)
	}

	// Reset the benchmark timer to exclude setup time
	b.ResetTimer()

	var ok bool
	for i := 0; i < b.N; i++ {
		signerVerifier := gq.NewSignerVerifier(matrix[i].rsaPublicKey, 256)
		ok = signerVerifier.Verify(signatures[i], []byte(matrix[i].private), []byte(matrix[i].message))
		if !ok {
			b.Fatal(fmt.Errorf("Failed to verify signature!"))
		}
	}

	// Avoid compiler optimisations eliminating the function under test and artificially lowering the run time of the benchmark
	// ref: https://dave.cheney.net/2013/06/30/how-to-write-benchmarks-in-go
	boolResult = ok
}

func generateTestMatrix(n, privateSize, messageSize int) ([]testTuple, error) {
	tests := []testTuple{}
	for i := 0; i < n; i++ {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}

		// Generate the test value on the fly before each benchmark iteration
		p, err := generateRandomBase64String(privateSize)
		if err != nil {
			return nil, err
		}

		m, err := generateRandomBase64String(messageSize)
		if err != nil {
			return nil, err
		}

		tests = append(tests, testTuple{rsaPublicKey: &key.PublicKey, private: p, message: m})
	}

	return tests, nil
}

func generateRandomBase64String(length int) (string, error) {
	// Calculate the number of random bytes required to generate the desired length of Base64 characters
	byteLength := (length * 6) / 8 // Each Base64 character represents 6 bits

	// Create a byte slice to hold the random bytes
	randomBytes := make([]byte, byteLength)

	// Read random bytes from the crypto/rand package
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	// Encode the random bytes as Base64
	randomBase64 := base64.RawURLEncoding.EncodeToString(randomBytes)

	// Truncate the result to the desired length
	if len(randomBase64) > length {
		randomBase64 = randomBase64[:length]
	}

	return randomBase64, nil
}
