package parties

import (
	"crypto/ecdsa"
)

type GithubOp struct {
}

func (h *GithubOp) RequestTokens(cicHash string, cb TokenCallback) error {
	// TODO: Add github action call here
	return nil
}

func (h *GithubOp) VerifyPKToken(pktCom []byte, cosPk *ecdsa.PublicKey) error {
	// TODO: Add github action call here
	return nil
}
