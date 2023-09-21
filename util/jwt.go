package util

import "fmt"

// SplitJWT splits a JWT token into the signing payload and the signature parts.
// The signing payload is `header || '.' || payload`.
func SplitJWT(jwt []byte) (signingPayload []byte, signature []byte, err error) {
	foundDots := 0
	var secondDot int
	for i, ch := range jwt {
		if ch == '.' {
			foundDots++
			if foundDots == 2 {
				secondDot = i
				break
			}
		}
	}
	if foundDots != 2 {
		return nil, nil, fmt.Errorf("jwt didn't have 2 dots")
	}

	signingPayload, signature = jwt[:secondDot], jwt[secondDot+1:]

	return signingPayload, signature, nil
}

// SplitDecodeJWT splits a JWT token into the signing payload and the signature parts,
// and base64-decodes the signature.
func SplitDecodeJWT(jwt []byte) (signingPayload []byte, signature []byte, err error) {
	signingPayload, sig, err := SplitJWT(jwt)
	if err != nil {
		return nil, nil, err
	}

	signature, err = Base64DecodeForJWT(sig)
	if err != nil {
		return nil, nil, err
	}

	return signingPayload, signature, nil
}
