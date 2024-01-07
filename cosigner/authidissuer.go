package cosigner

import (
	"crypto"
	"crypto/hmac"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync/atomic"
)

type AuthIDIssuer struct {
	authIdIter atomic.Uint64
	hmacKey    []byte
}

func NewAuthIDIssuer(hmacKey []byte) *AuthIDIssuer {
	return &AuthIDIssuer{
		authIdIter: atomic.Uint64{},
		hmacKey:    hmacKey,
	}
}

func (i *AuthIDIssuer) CreateAuthID(timeNow uint64) (string, error) {
	authIdInt := i.authIdIter.Add(1)
	iterAndTime := []byte{}
	iterAndTime = binary.LittleEndian.AppendUint64(iterAndTime, uint64(authIdInt))
	iterAndTime = binary.LittleEndian.AppendUint64(iterAndTime, timeNow)
	mac := hmac.New(crypto.SHA3_256.New, i.hmacKey)
	if n, err := mac.Write(iterAndTime); err != nil {
		return "", err
	} else if n != 16 {
		return "", fmt.Errorf("unexpected number of bytes read by HMAC, expected 16, got %d", n)
	} else {
		return hex.EncodeToString(mac.Sum(nil)), nil
	}
}
