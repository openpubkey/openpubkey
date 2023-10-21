package pktoken

import (
	"bytes"
	"encoding/json"
	"fmt"

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

type PKToken struct {
	raw []byte // the original, raw representation of the object

	Payload []byte
	Op      *jws.Signature
	Cic     *jws.Signature
	Cos     *jws.Signature
}

func New(idToken []byte, cicToken []byte) (*PKToken, error) {
	pkt := &PKToken{}
	if err := pkt.AddSignature(idToken, Oidc); err != nil {
		return nil, err
	}

	if err := pkt.AddSignature(cicToken, Cic); err != nil {
		return nil, err
	}

	return pkt, nil
}

func (p *PKToken) AddSignature(token []byte, sigType SignatureType) error {
	message, err := jws.Parse(token)
	if err != nil {
		return err
	}

	if p.Payload != nil && !bytes.Equal(p.Payload, message.Payload()) {
		return fmt.Errorf("payload in the GQ token (%s) does not match the existing payload in the PK Token (%s)", p.Payload, message.Payload())
	}

	public := jws.NewHeaders()
	public.Set(sigTypeHeader, string(sigType))
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

func (p *PKToken) OpSigType() SignatureType {
	sigType, _ := p.Op.ProtectedHeaders().Get(sigTypeHeader)
	return SignatureType(sigType.(string))
}

func (p *PKToken) OpJWSCompact() ([]byte, error) {
	message := jws.NewMessage().
		SetPayload(p.Payload).
		AppendSignature(p.Op)
	return jws.Compact(message)
}

func (p *PKToken) CicJWSCompact() ([]byte, error) {
	message := jws.NewMessage().
		SetPayload(p.Payload).
		AppendSignature(p.Cic)
	return jws.Compact(message)
}

func (p *PKToken) CosJWSCompact() ([]byte, error) {
	if p.Cos == nil {
		return nil, fmt.Errorf("no cosigner signature on PK Token")
	}

	message := jws.NewMessage().
		SetPayload(p.Payload).
		AppendSignature(p.Cos)
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

	p.Payload = parsed.Payload()

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
