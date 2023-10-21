package pktoken

import (
	"crypto/rsa"
	"fmt"

	"github.com/openpubkey/openpubkey/gq"
)

func (p *PKToken) VerifyGQSig(pubKey *rsa.PublicKey, gqSecurityParameter int) error {
	token, err := p.OpJWSCompact()
	if err != nil {
		return err
	}

	sv := gq.NewSignerVerifier(pubKey, gqSecurityParameter)
	ok := sv.VerifyJWT(token)
	if !ok {
		return fmt.Errorf("error verifying OP GQ signature on PK Token (ID Token invalid)")
	}
	return nil
}
