package pktoken

import (
	"context"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
)

func (p *PKToken) GetCicValues() (*clientinstance.Claims, error) {
	cicPH, err := p.Cic.ProtectedHeaders().AsMap(context.TODO())
	if err != nil {
		return nil, err
	}

	return clientinstance.ParseClaims(cicPH)
}

func (p *PKToken) VerifyCicSig() error {
	message := jws.NewMessage().
		SetPayload(p.Payload).
		AppendSignature(p.Cic)
	token, err := jws.Compact(message)
	if err != nil {
		return err
	}

	cic, err := p.GetCicValues()
	if err != nil {
		return err
	}

	_, err = jws.Verify(token, jws.WithKey(cic.PublicKey().Algorithm(), cic.PublicKey()))
	return err
}
