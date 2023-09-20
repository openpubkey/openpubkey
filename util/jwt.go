package util

import "fmt"

func SplitDecodeJWTSignature(jwt []byte) (signingPayload []byte, signature []byte, err error) {
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

	signingPayload, sig := jwt[:secondDot], jwt[secondDot+1:]

	signature, err = Base64DecodeForJWT(sig)
	if err != nil {
		return nil, nil, err
	}

	return signingPayload, signature, nil
}
