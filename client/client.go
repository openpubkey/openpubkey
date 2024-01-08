// Copyright 2024 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"
	"net/http"

	"github.com/awnumar/memguard"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
)

type OpkClient struct {
	Op   OpenIdProvider
	CosP *CosignerProvider
}

// Auth will attempt to authenticate to both the OpenID Provider and then the Cosigner.
// If no Cosigner supplied it will default to OidcAuth
func (o *OpkClient) Auth(
	ctx context.Context,
	signer crypto.Signer,
	alg jwa.KeyAlgorithm,
	extraClaims map[string]any,
	signGQ bool,
) (*pktoken.PKToken, error) {
	// If no Cosigner is set then do standard OIDC authentication
	if o.CosP == nil {
		return o.OidcAuth(ctx, signer, alg, extraClaims, signGQ)
	}

	// If a Cosigner is set then check that will support doing Cosigner auth
	if browserOp, ok := o.Op.(BrowserOpenIdProvider); !ok {
		return nil, fmt.Errorf("OP supplied does not have support for MFA Cosigner")
	} else {
		redirCh := make(chan string, 1)

		browserOp.HookHTTPSession(func(w http.ResponseWriter, r *http.Request) {
			redirectUri := <-redirCh
			http.Redirect(w, r, redirectUri, http.StatusFound)
		})

		pkt, err := o.OidcAuth(ctx, signer, alg, extraClaims, signGQ)
		if err != nil {
			return nil, err
		}
		return o.CosP.RequestToken(ctx, signer, pkt, redirCh)
	}
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
	err = jwkKey.Set(jwk.AlgorithmKey, alg)
	if err != nil {
		return nil, err
	}

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
	defer idToken.Destroy()

	// Sign over the payload from the ID token and client instance claims
	cicToken, err := cic.Sign(signer, alg, idToken.Bytes())
	if err != nil {
		return nil, fmt.Errorf("error creating cic token: %w", err)
	}

	opKey, err := o.Op.PublicKey(ctx, idToken.Bytes())
	if err != nil {
		return nil, fmt.Errorf("error getting OP public key: %w", err)
	}

	if signGQ {

		rsaPubKey := opKey.(*rsa.PublicKey)

		sv, err := gq.NewSignerVerifier(rsaPubKey, GQSecurityParameter)
		if err != nil {
			return nil, fmt.Errorf("error creating GQ signer: %w", err)
		}
		gqToken, err := sv.SignJWT(idToken.Bytes())
		if err != nil {
			return nil, fmt.Errorf("error creating GQ signature: %w", err)
		}
		idToken = memguard.NewBufferFromBytes(gqToken)
	}

	// Combine our ID token and signature over the cic to create our PK Token
	pkt, err := pktoken.New(idToken.Bytes(), cicToken, signGQ)
	if err != nil {
		return nil, fmt.Errorf("error creating PK Token: %w", err)
	}

	err = VerifyPKToken(ctx, pkt, o.Op)
	if err != nil {
		return nil, fmt.Errorf("error verifying PK Token: %w", err)
	}

	err = pkt.AddJKTHeader(opKey)
	if err != nil {
		return nil, fmt.Errorf("error adding JKT header: %w", err)
	}
	return pkt, nil
}
