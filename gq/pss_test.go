// Copyright 2024 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPSSEncodeExtractRoundTripAgainstStdlib signs a message with the standard
// library's RSASSA-PSS, recovers EM = s^e mod n, extracts the salt with
// extractPSSSalt, re-encodes EM with encodeEMSAPSS, and confirms it matches the
// EM produced by the signature. This pins our hand-rolled EMSA-PSS code to the
// stdlib's behaviour.
func TestPSSEncodeExtractRoundTripAgainstStdlib(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	message := []byte("the quick brown fox jumps over the lazy dog")
	digest := sha256.Sum256(message)

	// PS256: salt length equals the hash length (32 bytes).
	sig, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, digest[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
	require.NoError(t, err)

	// Sanity check the signature verifies with the stdlib.
	require.NoError(t, rsa.VerifyPSS(&priv.PublicKey, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}))

	// EM = s^e mod n
	emBits := priv.N.BitLen() - 1
	emLen := (emBits + 7) / 8
	sigInt := new(big.Int).SetBytes(sig)
	e := big.NewInt(int64(priv.E))
	emInt := new(big.Int).Exp(sigInt, e, priv.N)
	em := emInt.FillBytes(make([]byte, emLen))

	salt, err := extractPSSSalt(em, pssSaltLength, emBits)
	require.NoError(t, err)
	require.Len(t, salt, pssSaltLength)

	// Re-encoding the message with the recovered salt must reproduce EM exactly.
	reEncoded, err := encodeEMSAPSS(message, salt, emBits)
	require.NoError(t, err)
	require.Equal(t, em, reEncoded, "re-encoded EM does not match the signature's EM")
}

func TestEncodeEMSAPSSRoundTrip(t *testing.T) {
	message := []byte("hello world")
	salt := make([]byte, pssSaltLength)
	for i := range salt {
		salt[i] = byte(i)
	}
	emBits := 2047

	em, err := encodeEMSAPSS(message, salt, emBits)
	require.NoError(t, err)

	got, err := extractPSSSalt(em, pssSaltLength, emBits)
	require.NoError(t, err)
	require.Equal(t, salt, got)
}

func TestExtractPSSSaltRejectsMalformed(t *testing.T) {
	message := []byte("hello world")
	salt := make([]byte, pssSaltLength)
	emBits := 2047

	em, err := encodeEMSAPSS(message, salt, emBits)
	require.NoError(t, err)

	t.Run("bad trailer", func(t *testing.T) {
		bad := append([]byte(nil), em...)
		bad[len(bad)-1] = 0x00
		_, err := extractPSSSalt(bad, pssSaltLength, emBits)
		require.ErrorContains(t, err, "invalid trailer byte")
	})

	t.Run("wrong length", func(t *testing.T) {
		_, err := extractPSSSalt(em[:len(em)-1], pssSaltLength, emBits)
		require.ErrorContains(t, err, "inconsistent EM length")
	})

	t.Run("corrupted db breaks separator", func(t *testing.T) {
		bad := append([]byte(nil), em...)
		// Flip a byte near the start of maskedDB; after unmasking this corrupts
		// the PS/0x01 separator region.
		bad[1] ^= 0xff
		_, err := extractPSSSalt(bad, pssSaltLength, emBits)
		require.Error(t, err)
	})
}

func TestEncodeEMSAPSSTooSmall(t *testing.T) {
	// emBits too small to fit hLen + sLen + 2.
	_, err := encodeEMSAPSS([]byte("x"), make([]byte, pssSaltLength), 256)
	require.ErrorContains(t, err, "emLen too small")
}
