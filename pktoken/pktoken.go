package pktoken

import (
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"

	"github.com/openpubkey/openpubkey/util"

	_ "golang.org/x/crypto/sha3"
)

const sigTypeHeader = "sig_type"

type SignatureType string

const (
	Oidc SignatureType = "oidc"
	Gq   SignatureType = "oidc_gq"
	Cic  SignatureType = "cic"
	Cos  SignatureType = "cos"
)

type Signature = jws.Signature

type PKToken struct {
	raw []byte // the original, raw representation of the object

	Payload []byte     // decoded payload
	Op      *Signature // Provider Signature
	Cic     *Signature // Client Signature
	Cos     *Signature // Cosigner Signature
}

// kid isn't always present, and is only guaranteed to be unique within a given key set,
// so we can use the thumbprint of the key instead to identify it at verification time
func (p *PKToken) AddJKTHeader(opKey crypto.PublicKey) error {
	public, err := jwk.FromRaw(opKey)
	if err != nil {
		return fmt.Errorf("failed to create JWK from public key: %w", err)
	}
	thumbprint, err := public.Thumbprint(crypto.SHA256)
	if err != nil {
		return fmt.Errorf("failed to calculate thumbprint: %w", err)
	}
	return p.Op.PublicHeaders().Set("jkt", util.Base64EncodeForJWT(thumbprint))
}

func New(idToken []byte, cicToken []byte, isGQ bool) (*PKToken, error) {
	pkt := &PKToken{}

	sigType := Oidc
	if isGQ {
		sigType = Gq
	}

	if err := pkt.AddSignature(idToken, sigType); err != nil {
		return nil, err
	}

	if err := pkt.AddSignature(cicToken, Cic); err != nil {
		return nil, err
	}

	return pkt, nil
}

func (p *PKToken) Sign(
	sigType SignatureType,
	signer crypto.Signer,
	alg jwa.KeyAlgorithm,
	protected map[string]any,
) error {
	headers := jws.NewHeaders()
	for key, val := range protected {
		if err := headers.Set(key, val); err != nil {
			return fmt.Errorf("malformatted headers: %w", err)
		}
	}

	token, err := jws.Sign(
		p.Payload,
		jws.WithKey(
			alg,
			signer,
			jws.WithProtectedHeaders(headers),
		),
	)
	if err != nil {
		return err
	}

	return p.AddSignature(token, sigType)
}

func (p *PKToken) AddSignature(token []byte, sigType SignatureType) error {
	message, err := jws.Parse(token)
	if err != nil {
		return err
	}

	// If there is no payload, we set the provided token's payload as current, otherwise
	// we make sure that the new payload matches current
	if p.Payload == nil {
		p.Payload = message.Payload()
	} else if !bytes.Equal(p.Payload, message.Payload()) {
		return fmt.Errorf("payload in the GQ token (%s) does not match the existing payload in the PK Token (%s)", p.Payload, message.Payload())
	}

	public := jws.NewHeaders()
	if err := public.Set(sigTypeHeader, string(sigType)); err != nil {
		return err
	}
	signature := message.Signatures()[0].SetPublicHeaders(public)

	switch sigType {
	case Oidc, Gq:
		p.Op = signature
	case Cic:
		p.Cic = signature
	case Cos:
		p.Cos = signature
	default:
		return fmt.Errorf("unrecognized signature type: %s", string(sigType))
	}
	return nil
}

func (p *PKToken) ProviderSignatureType() (SignatureType, bool) {
	sigType, ok := p.Op.PublicHeaders().Get(sigTypeHeader)
	if !ok {
		return "", ok
	}

	return SignatureType(sigType.(string)), true
}

func (p *PKToken) Compact(sig *Signature) ([]byte, error) {
	message := jws.NewMessage().
		SetPayload(p.Payload).
		AppendSignature(sig)
	return jws.Compact(message)
}

func (p *PKToken) Hash() (string, error) {
	/*
		We set the raw variable when unmarshaling from json (the only current string representation of a
		PK Token) so when we hash we use the same representation that was given for consistency. When the
		token being hashed is a new PK Token, we marshal it ourselves. This can introduce some issues based
		on how different languages format their json strings.
	*/
	message := p.raw
	var err error
	if message == nil {
		message, err = json.Marshal(p)
		if err != nil {
			return "", err
		}
	}

	hash := util.B64SHA3_256(message)
	return string(hash), nil
}

func (p *PKToken) MarshalJSON() ([]byte, error) {
	message := jws.NewMessage().
		SetPayload(p.Payload).
		AppendSignature(p.Op).
		AppendSignature(p.Cic)

	if p.Cos != nil {
		message.AppendSignature(p.Cos)
	}

	return json.Marshal(message)
}

func (p *PKToken) UnmarshalJSON(data []byte) error {
	var parsed jws.Message
	if err := json.Unmarshal(data, &parsed); err != nil {
		return err
	}

	p.Payload = parsed.Payload() // base64 decoded

	opCount := 0
	cicCount := 0
	cosCount := 0
	for _, signature := range parsed.Signatures() {
		sigHeader, ok := signature.PublicHeaders().Get(sigTypeHeader)
		if !ok {
			return fmt.Errorf(`pk token signature is missing required "%s" header as public header`, sigTypeHeader)
		}

		sigHeaderString, ok := sigHeader.(string)
		if !ok {
			return fmt.Errorf(`provided "%s" is of wrong type, expected string`, sigTypeHeader)
		}

		switch SignatureType(sigHeaderString) {
		case Oidc:
			opCount += 1
			p.Op = signature
		case Gq:
			opCount += 1
			p.Op = signature
		case Cic:
			cicCount += 1
			p.Cic = signature
		case Cos:
			cosCount += 1
			p.Cos = signature
		default:
			return fmt.Errorf("unrecognized signature types: %s", sigHeaderString)
		}
	}

	// Do some signature count verifications
	if opCount == 0 {
		return fmt.Errorf(`at least one signature of type "oidc" or "oidc_gq" is required`)
	} else if opCount > 1 {
		return fmt.Errorf(`only one signature of type "oidc" or "oidc_gq" is allowed, found %d`, opCount)
	}

	if cicCount == 0 {
		return fmt.Errorf(`at least one signature of type "cic" is required`)
	} else if cicCount > 1 {
		return fmt.Errorf(`only one signature of type "cic" is allowed, found %d`, cicCount)
	}

	if cosCount > 1 {
		return fmt.Errorf(`only one signature of type "cos" is allowed, found %d`, cosCount)
	}

	return nil
}
