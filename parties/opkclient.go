package parties

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"
	"net/http"

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
	Pkt           *pktoken.PKToken
	SigningKey    crypto.Signer
	UserPublicKey jwk.Key // Requires "alg" header to be set
	Gq            bool
	Op            OpenIdProvider
	MFACosigner   MFACos
}

func (o *OpkClient) OidcAuth() ([]byte, error) {
	// Make sure our JWK has the algorithm set
	if o.UserPublicKey.Algorithm().String() == "" {
		return nil, fmt.Errorf("user JWK requires algorithm to be set")
	}

	// User uses key pair to generate client instance claims
	cic, err := clientinstance.NewClaims(o.UserPublicKey, map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate client instance claims: %w", err)
	}

	// Define our OIDC nonce as a commitment to our client instance claims
	nonce, err := cic.Commitment()
	if err != nil {
		return nil, fmt.Errorf("error getting nonce: %w", err)
	}

	// Use that commitment nonce to complete the OIDC flow and get an ID token from the provider
	idToken, err := o.Op.RequestTokens(nonce)
	if err != nil {
		return nil, fmt.Errorf("error requesting ID Token: %w", err)
	}

	// User signs the payload from the ID token
	cicToken, err := cic.Sign(o.SigningKey, o.UserPublicKey.Algorithm(), idToken)
	if err != nil {
		return nil, fmt.Errorf("error creating cic token: %w", err)
	}

	// Combine our ID token and our signature over the cic to create our PK Token
	o.Pkt, err = pktoken.New(idToken, cicToken)
	if err != nil {
		return nil, fmt.Errorf("error creating PK Token: %w", err)
	}

	if o.Gq {
		opKey, err := o.Op.PublicKey(idToken)
		if err != nil {
			return nil, fmt.Errorf("error getting OP public key: %w", err)
		}
		rsaPubKey := opKey.(*rsa.PublicKey)

		sv := gq.NewSignerVerifier(rsaPubKey, gqSecurityParameter)
		gqSig, err := sv.SignJWTIdentity(idToken)
		if err != nil {
			return nil, fmt.Errorf("error creating GQ signature: %w", err)
		}

		o.Pkt.OpSig = gqSig
		o.Pkt.OpSigGQ = true
		// TODO: make sure old value of OpSig is fully gone from memory
	}

	pktJSON, err := o.Pkt.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("error serializing PK Token: %w", err)
	}

	_, err = o.Op.VerifyPKToken(pktJSON, nil)
	if err != nil {
		return nil, fmt.Errorf("error verifying PK Token: %w", err)
	}
	return pktJSON, nil
}

type TokenCallback func(tokens *oidc.Tokens[*oidc.IDTokenClaims])

type PublicKey interface {
	Equal(x crypto.PublicKey) bool
}

// Interface for interacting with the OP (OpenID Provider)
type OpenIdProvider interface {
	RequestTokens(cicHash string) ([]byte, error)
	VerifyPKToken(pktJSON []byte, cosPk *ecdsa.PublicKey) (map[string]any, error)
	PublicKey(idt []byte) (PublicKey, error)
}

func (o *OpkClient) RequestCert() ([]byte, error) {
	pktJson, err := o.Pkt.ToJSON()
	if err != nil {
		return nil, err
	}

	uri := fmt.Sprintf("http://localhost:3002/cert?pkt=%s", pktJson)
	resp, err := http.Get(uri)
	if err != nil {
		fmt.Printf("MFA request failed: %s\n", err)
		return nil, err
	}
	defer resp.Body.Close()
	certBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return certBytes, nil
}
