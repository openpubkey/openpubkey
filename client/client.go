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
	"github.com/lestrrat-go/jwx/v2/jws"

	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/util"
)

// OpkClient is the OpenPubkey client
type OpkClient struct {
	Op     OpenIdProvider
	cosP   *CosignerProvider
	signer crypto.Signer
	alg    jwa.KeyAlgorithm
	signGQ bool // Default is false
}

// ClientOpts contains options for constructing an OpkClient
type ClientOpts func(o *OpkClient)

// WithSigner allows the caller to inject their own signer and algorithm.
// Use this option if to generate to bring your own user key pair. If this
// option is not set the OpkClient constructor will automatically generate
// a signer, i.e., key pair.
// Example use:
//
//	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
//	WithSigner(signer, jwa.ES256)
func WithSigner(signer crypto.Signer, alg jwa.KeyAlgorithm) ClientOpts {
	return func(o *OpkClient) {
		o.signer = signer
		o.alg = alg
	}
}

// WithSignGQ specifies if the OPs signature on the ID Token should be replaced
// with a GQ signature by the client.
func WithSignGQ(signGQ bool) ClientOpts {
	return func(o *OpkClient) {
		o.signGQ = signGQ
	}
}

// WithCosignerProvider specifies what cosigner provider should be used to
// cosign the PK Token. If this is not specified then the cosigning setup
// is skipped.
func WithCosignerProvider(cosP *CosignerProvider) ClientOpts {
	return func(o *OpkClient) {
		o.cosP = cosP
	}
}

// New returns a new client.OpkClient. The op argument should be the
// OpenID Provider you want to authenticate against.
func New(op OpenIdProvider, opts ...ClientOpts) (*OpkClient, error) {
	client := &OpkClient{
		Op:     op,
		signer: nil,
		alg:    nil,
		signGQ: false,
	}

	for _, applyOpt := range opts {
		applyOpt(client)
	}

	if client.alg == nil && client.signer != nil {
		return nil, fmt.Errorf("signer specified but alg is nil, must specify alg of signer")
	}

	if client.signer == nil {
		// Generate signer for specified alg. If no alg specified, defaults to ES256
		if client.alg == nil {
			client.alg = jwa.ES256
		}

		signer, err := util.GenKeyPair(client.alg)
		if err != nil {
			return nil, fmt.Errorf("failed to create key pair for client: %w ", err)
		}
		client.signer = signer
	}

	return client, nil
}

type AuthOptsStruct struct {
	extraClaims map[string]any
}
type AuthOpts func(a *AuthOptsStruct)

// WithExtraClaim specifies additional values to be included in the
// CIC. These claims will be include in the CIC protected header and
// will be hashed into the commitment claim in the ID Token. The
// commitment claim is typically the nonce or aud claim in the ID Token.
// Example use:
//
//	WithExtraClaim("claimKey", "claimValue")
func WithExtraClaim(k string, v string) AuthOpts {
	return func(a *AuthOptsStruct) {
		if a.extraClaims == nil {
			a.extraClaims = map[string]any{}
		}
		a.extraClaims[k] = v
	}
}

// Auth returns a PK Token by running the OpenPubkey protocol. It will first
// authenticate to the configured OpenID Provider (OP) and receive an ID Token.
// Using this ID Token it will generate a PK Token. If a Cosigner has been
// configured it will also attempt to get the PK Token cosigned.
func (o *OpkClient) Auth(ctx context.Context, opts ...AuthOpts) (*pktoken.PKToken, error) {
	authOpts := &AuthOptsStruct{
		extraClaims: map[string]any{},
	}
	for _, applyOpt := range opts {
		applyOpt(authOpts)
	}

	// If no Cosigner is set then do standard OIDC authentication
	if o.cosP == nil {
		return o.OidcAuth(ctx, o.signer, o.alg, authOpts.extraClaims, o.signGQ)
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

		pkt, err := o.OidcAuth(ctx, o.signer, o.alg, authOpts.extraClaims, o.signGQ)
		if err != nil {
			return nil, err
		}
		return o.cosP.RequestToken(ctx, o.signer, pkt, redirCh)
	}
}

// OidcAuth exists only for backwards compatibility. Use Auth instead.
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

	headersB64, _, _, err := jws.SplitCompact(idToken.Bytes())
	if err != nil {
		return nil, fmt.Errorf("error getting original headers: %w", err)
	}

	headers := jws.NewHeaders()
	err = parseJWTSegment(headersB64, &headers)
	if err != nil {
		return nil, err
	}

	opKey, err := o.Op.PublicKey(ctx, headers)
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
	pkt, err := pktoken.New(idToken.Bytes(), cicToken)
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

// GetOp returns the OpenID Provider the OpkClient has been configured to use
func (o *OpkClient) GetOp() OpenIdProvider {
	return o.Op
}

// GetCosP returns the MFA Cosigner Provider the OpkClient has been
// configured to use
func (o *OpkClient) GetCosP() *CosignerProvider {
	return o.cosP
}

// GetSigner returns the client's key pair (Public Key, Signing Key)
func (o *OpkClient) GetSigner() crypto.Signer {
	return o.signer
}

// GetAlg returns the algorithm of the client's key pair
// (Public Key, Signing Key)
func (o *OpkClient) GetAlg() jwa.KeyAlgorithm {
	return o.alg
}

// GetSignGQ returns if the client is using GQ signatures to hide the OPs
// signature on the ID Token in this PK Token.
func (o *OpkClient) GetSignGQ() bool {
	return o.signGQ
}
