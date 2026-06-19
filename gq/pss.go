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
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// pssSaltLength is the salt length used by PS256 (RSASSA-PSS using SHA-256).
// JWA fixes the salt length to the hash output length, i.e. SHA-256 = 32 bytes.
const pssSaltLength = sha256.Size

// These functions implement the pieces of EMSA-PSS (RFC 8017 §9.1) that GQ needs
// to reconstruct the encoded message (EM) of a PS256-signed JWT.
//
// Unlike PKCS#1 v1.5 (see encodePKCS1v15 in rsa.go), PSS encoding mixes in a
// random salt. GQ strips the OP's RSA signature s, but the salt lives inside s,
// so the GQ signer extracts the salt (extractPSSSalt) and carries it in the GQ
// protected header. The verifier then rebuilds EM (encodeEMSAPSS) from the
// signing payload + carried salt. EM is always recomputed from the message, so
// tampering with either the payload or the salt changes EM and fails GQ verify.
//
// The hash is hardcoded to SHA-256 to match GQ256 and PS256.

// mgf1SHA256 is the MGF1 mask generation function (RFC 8017 §B.2.1) using
// SHA-256, producing a mask of the requested length.
func mgf1SHA256(seed []byte, length int) []byte {
	mask := make([]byte, 0, length)
	var counter [4]byte
	for i := 0; len(mask) < length; i++ {
		binary.BigEndian.PutUint32(counter[:], uint32(i))
		h := sha256.New()
		h.Write(seed)
		h.Write(counter[:])
		mask = h.Sum(mask)
	}
	return mask[:length]
}

// encodeEMSAPSS produces the PSS-encoded message EM for the given message and
// salt, following EMSA-PSS-ENCODE (RFC 8017 §9.1.1) with SHA-256. emBits is the
// maximal bit length of the integer EM, i.e. modBits - 1.
func encodeEMSAPSS(message []byte, salt []byte, emBits int) ([]byte, error) {
	hLen := sha256.Size
	sLen := len(salt)
	emLen := (emBits + 7) / 8

	if emLen < hLen+sLen+2 {
		return nil, fmt.Errorf("pss encoding error: emLen too small (emLen=%d, hLen=%d, sLen=%d)", emLen, hLen, sLen)
	}

	mHash := sha256.Sum256(message)

	// M' = (0x) 00 00 00 00 00 00 00 00 || mHash || salt
	mPrime := make([]byte, 0, 8+hLen+sLen)
	mPrime = append(mPrime, make([]byte, 8)...)
	mPrime = append(mPrime, mHash[:]...)
	mPrime = append(mPrime, salt...)
	hArr := sha256.Sum256(mPrime)
	h := hArr[:]

	// DB = PS || 0x01 || salt, length emLen - hLen - 1
	psLen := emLen - sLen - hLen - 2
	db := make([]byte, emLen-hLen-1)
	db[psLen] = 0x01
	copy(db[psLen+1:], salt)

	dbMask := mgf1SHA256(h, emLen-hLen-1)
	for i := range db {
		db[i] ^= dbMask[i]
	}
	// Clear the leftmost 8*emLen - emBits bits of the leftmost byte.
	db[0] &= 0xff >> (uint(8*emLen) - uint(emBits))

	// EM = maskedDB || H || 0xbc
	em := make([]byte, emLen)
	copy(em[:emLen-hLen-1], db)
	copy(em[emLen-hLen-1:emLen-1], h)
	em[emLen-1] = 0xbc
	return em, nil
}

// extractPSSSalt recovers the salt from a PSS-encoded message EM, following the
// decode half of EMSA-PSS-VERIFY (RFC 8017 §9.1.2) with SHA-256. sLen is the
// expected salt length and emBits is modBits - 1. It validates the structure of
// EM and errors on malformed input. It does not recompute/compare H against a
// message hash; GQ verification binds the salt to the message by recomputing EM.
func extractPSSSalt(em []byte, sLen, emBits int) ([]byte, error) {
	hLen := sha256.Size
	emLen := (emBits + 7) / 8

	if emLen != len(em) {
		return nil, fmt.Errorf("pss decode error: inconsistent EM length (got %d, want %d)", len(em), emLen)
	}
	if emLen < hLen+sLen+2 {
		return nil, fmt.Errorf("pss decode error: emLen too small (emLen=%d, hLen=%d, sLen=%d)", emLen, hLen, sLen)
	}
	if em[emLen-1] != 0xbc {
		return nil, fmt.Errorf("pss decode error: invalid trailer byte")
	}

	maskedDB := em[:emLen-hLen-1]
	h := em[emLen-hLen-1 : emLen-1]

	bitMask := byte(0xff >> (uint(8*emLen) - uint(emBits)))
	if maskedDB[0]&^bitMask != 0 {
		return nil, fmt.Errorf("pss decode error: leftmost bits of maskedDB are not zero")
	}

	dbMask := mgf1SHA256(h, emLen-hLen-1)
	db := make([]byte, len(maskedDB))
	for i := range maskedDB {
		db[i] = maskedDB[i] ^ dbMask[i]
	}
	db[0] &= bitMask

	// DB = PS (zeros) || 0x01 || salt
	psLen := emLen - hLen - sLen - 2
	for _, b := range db[:psLen] {
		if b != 0x00 {
			return nil, fmt.Errorf("pss decode error: non-zero byte in PS")
		}
	}
	if db[psLen] != 0x01 {
		return nil, fmt.Errorf("pss decode error: missing 0x01 separator")
	}

	salt := make([]byte, sLen)
	copy(salt, db[len(db)-sLen:])
	return salt, nil
}
