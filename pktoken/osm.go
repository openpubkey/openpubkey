package pktoken

import (
	"crypto"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jws"
)

func (p *PKToken) NewSignedMessage(content []byte, signer crypto.Signer) ([]byte, error) {
	alg, _, _, err := p.GetCicValues()
	if err != nil {
		return nil, err
	}

	pktHash, err := p.Hash()
	if err != nil {
		return nil, err
	}

	// Create our headers as defined by section 3.5 of the OpenPubkey paper
	protected := jws.NewHeaders()
	if err := protected.Set("alg", alg); err != nil {
		return nil, err
	}
	if err := protected.Set("kid", string(pktHash)); err != nil {
		return nil, err
	}
	if err := protected.Set("typ", "osm"); err != nil {
		return nil, err
	}

	return jws.Sign(
		content,
		jws.WithKey(
			alg,
			signer,
			jws.WithProtectedHeaders(protected),
		),
	)
}

func (p *PKToken) VerifySignedMessage(osm []byte) ([]byte, error) {
	alg, _, upk, err := p.GetCicValues()
	if err != nil {
		return nil, err
	}

	message, err := jws.Parse(osm)
	if err != nil {
		return nil, err
	}

	// Check that our OSM headers are correct
	if len(message.Signatures()) != 1 {
		return nil, fmt.Errorf("expected only one signature on jwt, received %d", len(message.Signatures()))
	}
	protected := message.Signatures()[0].ProtectedHeaders()

	// Verify typ header matches expected "osm" value
	typ, ok := protected.Get("typ")
	if !ok {
		return nil, fmt.Errorf("missing required header `typ`")
	}
	if typ != "osm" {
		return nil, fmt.Errorf(`incorrect "typ" header, expected "osm" but recieved %s`, typ)
	}

	// Verify key algorithm header matches cic
	if protected.Algorithm() != alg {
		return nil, fmt.Errorf(`incorrect "alg" header, expected %s but recieved %s`, alg, protected.Algorithm())
	}

	// Verify kid header matches hash of pktoken
	kid, ok := protected.Get("kid")
	if !ok {
		return nil, fmt.Errorf("missing required header `kid`")
	}

	pktHash, err := p.Hash()
	if err != nil {
		return nil, fmt.Errorf("unable to hash PK Token: %w", err)
	}

	if kid != string(pktHash) {
		return nil, fmt.Errorf(`incorrect "kid" header, expected %s but recieved %s`, pktHash, kid)
	}

	_, err = jws.Verify(osm, jws.WithKey(alg, upk))
	if err != nil {
		return nil, err
	}

	// Return the osm payload
	return message.Payload(), nil
}
