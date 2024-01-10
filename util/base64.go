package util

import (
	"encoding/base64"
)

var standardEncoding = base64.StdEncoding.Strict()
var rawURLEncoding = base64.RawURLEncoding.Strict()

func Base64Encode(decoded []byte) []byte {
	return base64Encode(decoded, standardEncoding)
}

func Base64Decode(encoded []byte) ([]byte, error) {
	return base64Decode(encoded, standardEncoding)
}

func Base64EncodeForJWT(decoded []byte) []byte {
	return base64Encode(decoded, rawURLEncoding)
}

func Base64DecodeForJWT(encoded []byte) ([]byte, error) {
	return base64Decode(encoded, rawURLEncoding)
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
