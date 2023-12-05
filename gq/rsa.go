package gq

import (
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
)

// Hardcoded padding prefix for SHA-256 from https://github.com/golang/go/blob/eca5a97340e6b475268a522012f30e8e25bb8b8f/src/crypto/rsa/pkcs1v15.go#L268
var prefix = []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}

// encodePKCS1v15 is taken from the go stdlib, see [crypto/rsa.SignPKCS1v15].
//
// https://github.com/golang/go/blob/eca5a97340e6b475268a522012f30e8e25bb8b8f/src/crypto/rsa/pkcs1v15.go#L287-L317
func encodePKCS1v15(k int, data []byte) []byte {
	hashLen := crypto.SHA256.Size()
	tLen := len(prefix) + hashLen

	// EM = 0x00 || 0x01 || PS || 0x00 || T
	em := make([]byte, k)
	em[1] = 1
	for i := 2; i < k-tLen-1; i++ {
		em[i] = 0xff
	}
	copy(em[k-tLen:k-hashLen], prefix)

	hashed := sha256.Sum256(data)
	copy(em[k-hashLen:k], hashed[:])
	return em
}

// func emsaPSSEncode(mHash []byte, emBits int, salt []byte, hash hash.Hash) ([]byte, error) {
func encodePSS(emBits int, data []byte) []byte {
	// See RFC 8017, Section 9.1.1.

	hLen := crypto.SHA1.Size()
	salt := []byte("")
	sLen := 0
	emLen := (emBits + 7) / 8

	// 1.  If the length of M is greater than the input limitation for the
	//     hash function (2^61 - 1 octets for SHA-1), output "message too
	//     long" and stop.
	//
	// 2.  Let mHash = Hash(M), an octet string of length hLen.

	if len(data) != hLen {
		fmt.Println("Oh no 1")
		return nil
	}

	// 3.  If emLen < hLen + sLen + 2, output "encoding error" and stop.

	if emLen < hLen+sLen+2 {
		fmt.Println("Oh no 2")
		return nil
	}

	em := make([]byte, emLen)
	psLen := emLen - sLen - hLen - 2
	db := em[:psLen+1+sLen]
	h := em[psLen+1+sLen : emLen-1]

	// 4.  Generate a random octet string salt of length sLen; if sLen = 0,
	//     then salt is the empty string.
	//
	// 5.  Let
	//       M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
	//
	//     M' is an octet string of length 8 + hLen + sLen with eight
	//     initial zero octets.
	//
	// 6.  Let H = Hash(M'), an octet string of length hLen.

	var prefix [8]byte

	hashFn := sha1.New()
	hashFn.Write(prefix[:])
	hashFn.Write(data)
	hashFn.Write(salt)

	h = hashFn.Sum(h[:0])
	hashFn.Reset()

	// 7.  Generate an octet string PS consisting of emLen - sLen - hLen - 2
	//     zero octets. The length of PS may be 0.
	//
	// 8.  Let DB = PS || 0x01 || salt; DB is an octet string of length
	//     emLen - hLen - 1.

	db[psLen] = 0x01
	copy(db[psLen+1:], salt)

	// 9.  Let dbMask = MGF(H, emLen - hLen - 1).
	//
	// 10. Let maskedDB = DB \xor dbMask.

	mgf1XOR(db, hashFn, h)

	// 11. Set the leftmost 8 * emLen - emBits bits of the leftmost octet in
	//     maskedDB to zero.

	db[0] &= 0xff >> (8*emLen - emBits)

	// 12. Let EM = maskedDB || H || 0xbc.
	em[emLen-1] = 0xbc

	// 13. Output EM.
	return em
}

func mgf1XOR(out []byte, hash hash.Hash, seed []byte) {
	var counter [4]byte
	var digest []byte

	done := 0
	for done < len(out) {
		hash.Write(seed)
		hash.Write(counter[0:4])
		digest = hash.Sum(digest[:0])
		hash.Reset()

		for i := 0; i < len(digest) && done < len(out); i++ {
			out[done] ^= digest[i]
			done++
		}
		incCounter(&counter)
	}
}

func incCounter(c *[4]byte) {
	if c[3]++; c[3] != 0 {
		return
	}
	if c[2]++; c[2] != 0 {
		return
	}
	if c[1]++; c[1] != 0 {
		return
	}
	c[0]++
}
