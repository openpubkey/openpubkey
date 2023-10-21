package parties

import (
	"crypto"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/zitadel/oidc/v2/pkg/oidc"

	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
)

const gqSecurityParameter = 256

// Interface for interacting with the MFA Cosigner (MFACos)
type MFACos interface {
	// place holder for MFA Cosigner
	// TODO: Add MFA Cosigner
}

type OpkClient struct {
	Op          OpenIdProvider
	MFACosigner MFACos
}

func (o *OpkClient) OidcAuth(
	signer crypto.Signer,
	alg jwa.KeyAlgorithm,
	extraClaims map[string]any,
	signGQ bool,
) (*pktoken.PKToken, error) {
	// Use our signing key to generate a JWK key with the alg header set
	jwkKey, err := jwk.PublicKeyOf(signer)
	if err != nil {
		return nil, err
	}
	jwkKey.Set(jwk.AlgorithmKey, alg)

	// Use provided public key to generate client instance claims
	cic, err := clientinstance.NewClaims(jwkKey, extraClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate client instance claims: %w", err)
	}

	// Define our OIDC nonce as a commitment to the client instance claims
	nonce, err := cic.Commitment()
	if err != nil {
		return nil, fmt.Errorf("error getting nonce: %w", err)
	}

	// Use the commitment nonce to complete the OIDC flow and get an ID token from the provider
	idToken, err := o.Op.RequestTokens(nonce)
	if err != nil {
		return nil, fmt.Errorf("error requesting ID Token: %w", err)
	}

	// Sign over the payload from the ID token and client instance claims
	cicToken, err := cic.Sign(signer, alg, idToken)
	if err != nil {
		return nil, fmt.Errorf("error creating cic token: %w", err)
	}

	// Combine our ID token and signature over the cic to create our PK Token
	pkt, err := pktoken.New(idToken, cicToken)
	if err != nil {
		return nil, fmt.Errorf("error creating PK Token: %w", err)
	}

	if signGQ {
		opKey, err := o.Op.PublicKey(idToken)
		if err != nil {
			return nil, fmt.Errorf("error getting OP public key: %w", err)
		}
		rsaPubKey := opKey.(*rsa.PublicKey)

		sv := gq.NewSignerVerifier(rsaPubKey, gqSecurityParameter)
		gqToken, err := sv.SignJWT(idToken)
		if err != nil {
			return nil, fmt.Errorf("error creating GQ signature: %w", err)
		}

		pkt.AddSignature(gqToken, pktoken.Gq)
		// TODO: make sure old value of OpSig is fully gone from memory
	}

	err = o.Op.VerifyPKToken(pkt, nil)
	if err != nil {
		return nil, fmt.Errorf("error verifying PK Token: %w", err)
	}

	return pkt, nil
}

type TokenCallback func(tokens *oidc.Tokens[*oidc.IDTokenClaims])

type PublicKey interface {
	Equal(x crypto.PublicKey) bool
}

// Interface for interacting with the OP (OpenID Provider)
type OpenIdProvider interface {
	RequestTokens(cicHash string) ([]byte, error)
	VerifyPKToken(pkt *pktoken.PKToken, cosPk crypto.PublicKey) error
	PublicKey(idt []byte) (PublicKey, error)
}

func (o *OpkClient) RequestCert() ([]byte, error) {
	return nil, fmt.Errorf("cosigning currently unsupported")

	// uri := fmt.Sprintf("http://localhost:3002/cert?pkt=%s", o.PktJson)
	// resp, err := http.Get(uri)
	// if err != nil {
	// 	return nil, fmt.Errorf("MFA request failed: %s", err)
	// }
	// defer resp.Body.Close()
	// return io.ReadAll(resp.Body)
}
