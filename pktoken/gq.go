package pktoken

import (
	"crypto/rsa"
	"fmt"

	"github.com/openpubkey/openpubkey/gq"
)

func (p *PKToken) VerifyGQSig(pubKey *rsa.PublicKey, gqSecurityParameter int) error {
	sv, err := gq.NewSignerVerifier(pubKey, gqSecurityParameter)
	if err != nil {
		return err
	}
	ok := sv.VerifyJWT(p.OpToken)
	if !ok {
		return fmt.Errorf("error verifying OP GQ signature on PK Token (ID Token invalid)")
	}
	return nil
}
