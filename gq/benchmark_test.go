package gq_test

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func BenchmarkSigning(b *testing.B) {
	// Perform the operations you want to benchmark
	for i := 0; i < b.N; i++ {
		_ = YourFunctionToBenchmark(42) // Call your function
	}
}

func BenchmarkVerifying(b *testing.B) {
	tests := []string{}
	for i := 0; i < b.N; i++ {
		// Generate the test value on the fly before each benchmark iteration
		randomBase64String, err := generateRandomBase64String(32)
		if err != nil {
			b.Fatalf("Error: %v", err)
		}
		// Perform your benchmarked operation using randomBase64String
		_ = randomBase64String
	}

	// Reset the benchmark timer to exclude setup time
	b.ResetTimer()

	var result error
	for i := 0; i < b.N; i++ {
		_ = YourFunctionToBenchmark(42) // Call your function
	}
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
