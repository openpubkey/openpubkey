package util

import (
	"encoding/base64"
)

func Base64Encode(decoded []byte) []byte {
	return base64Encode(decoded, base64.StdEncoding.Strict())
}

func Base64Decode(encoded []byte) ([]byte, error) {
	return base64Decode(encoded, base64.StdEncoding.Strict())
}

func Base64EncodeForJWT(decoded []byte) []byte {
	return base64Encode(decoded, base64.RawURLEncoding.Strict())
}

func Base64DecodeForJWT(encoded []byte) ([]byte, error) {
	return base64Decode(encoded, base64.RawURLEncoding.Strict())
}

func base64Encode(decoded []byte, encoding *base64.Encoding) []byte {
	encoded := make([]byte, encoding.EncodedLen(len(decoded)))
	encoding.Encode(encoded, decoded)
	return encoded
}

func base64Decode(encoded []byte, encoding *base64.Encoding) ([]byte, error) {
	decoded := make([]byte, encoding.DecodedLen(len(encoded)))
	n, err := encoding.Decode(decoded, encoded)
	if err != nil {
		return nil, err
	}
	return decoded[:n], nil
}
