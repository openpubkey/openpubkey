package pktoken

import (
	"crypto/rsa"
	"fmt"

	"github.com/openpubkey/openpubkey/gq"
)

func (p *PKToken) VerifyGQSig(pubKey *rsa.PublicKey) error {
	alg, ok := p.ProviderAlgorithm()
	if !ok {
		return fmt.Errorf("missing provider algorithm header")
	}

	if alg != gq.GQ256 {
		return fmt.Errorf("signature is not of type GQ")
	}

	token, err := p.Compact(p.Op)
	if err != nil {
		return err
	}

	sv, err := gq.New256SignerVerifier(pubKey)
	if err != nil {
		return err
	}
	ok = sv.VerifyJWT(token)
	if !ok {
		return fmt.Errorf("error verifying OP GQ signature on PK Token (ID Token invalid)")
	}
	return nil
}
