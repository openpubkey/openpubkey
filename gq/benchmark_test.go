// Copyright 2024 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gq

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"
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
	require.NoError(b, err)

	// Reset the benchmark timer to exclude setup time
	b.ResetTimer()

	var signerVerifier SignerVerifier
	for i := 0; i < b.N; i++ {
		signerVerifier, err = NewSignerVerifier(matrix[i].rsaPublicKey, 256)
		require.NoError(b, err)
		_, err = signerVerifier.SignJWT(matrix[i].token)
		require.NoError(b, err)
	}

	// Avoid compiler optimisations eliminating the function under test and artificially lowering the run time of the benchmark
	// ref: https://dave.cheney.net/2013/06/30/how-to-write-benchmarks-in-go
	result = err
}

func BenchmarkVerifying(b *testing.B) {
	// Generate test matrix
	matrix, err := generateTestMatrix(b.N)
	require.NoError(b, err)

	// Generate signatures using matrix
	gqSignedTokens := [][]byte{}
	for i := 0; i < b.N; i++ {
		signerVerifier, err := NewSignerVerifier(matrix[i].rsaPublicKey, 256)
		require.NoError(b, err)
		sig, err := signerVerifier.SignJWT(matrix[i].token)
		require.NoError(b, err)

		gqSignedTokens = append(gqSignedTokens, sig)
	}

	// Reset the benchmark timer to exclude setup time
	b.ResetTimer()

	var ok bool
	for i := 0; i < b.N; i++ {
		signerVerifier, err := NewSignerVerifier(matrix[i].rsaPublicKey, 256)
		require.NoError(b, err)
		ok = signerVerifier.VerifyJWT(gqSignedTokens[i])
		require.True(b, ok, "Failed to verify signature!")
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
