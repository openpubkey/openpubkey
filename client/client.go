package client

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
)

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
	ctx context.Context,
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
	nonce, err := cic.Hash()
	if err != nil {
		return nil, fmt.Errorf("error getting nonce: %w", err)
	}

	// Use the commitment nonce to complete the OIDC flow and get an ID token from the provider
	idToken, err := o.Op.RequestTokens(ctx, string(nonce))
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
		opKey, err := o.Op.PublicKey(ctx, idToken)
		if err != nil {
			return nil, fmt.Errorf("error getting OP public key: %w", err)
		}
		rsaPubKey := opKey.(*rsa.PublicKey)

		sv := gq.NewSignerVerifier(rsaPubKey, GQSecurityParameter)
		gqToken, err := sv.SignJWT(idToken)
		if err != nil {
			return nil, fmt.Errorf("error creating GQ signature: %w", err)
		}

		pkt.AddSignature(gqToken, pktoken.Gq)
		// TODO: make sure old value of OpSig is fully gone from memory
	}

	err = VerifyPKToken(ctx, pkt, o.Op)
	if err != nil {
		return nil, fmt.Errorf("error verifying PK Token: %w", err)
	}

	return pkt, nil
}
