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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/awnumar/memguard"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
	oidcclient "github.com/zitadel/oidc/v2/pkg/client"
)

const GQSecurityParameter = 256

var ErrNonGQUnsupported = fmt.Errorf("non-GQ signatures are not supported")

type OidcClaims struct {
	Issuer     string `json:"iss"`
	Subject    string `json:"sub"`
	Audience   string `json:"-"`
	Expiration int64  `json:"exp"`
	IssuedAt   int64  `json:"iat"`
	Email      string `json:"email,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
	Username   string `json:"preferred_username,omitempty"`
	FirstName  string `json:"given_name,omitempty"`
	LastName   string `json:"family_name,omitempty"`
}

// Implement UnmarshalJSON for custom handling during JSON unmarshaling
func (id *OidcClaims) UnmarshalJSON(data []byte) error {
	// unmarshal audience claim seperately to account for []string, https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
	type Alias OidcClaims
	aux := &struct {
		Audience any `json:"aud"`
		*Alias
	}{
		Alias: (*Alias)(id),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	switch t := aux.Audience.(type) {
	case string:
		id.Audience = t
	case []any:
		audList := []string{}
		for _, v := range t {
			audList = append(audList, v.(string))
		}
		id.Audience = strings.Join(audList, ",")
	default:
		id.Audience = ""
	}

	return nil
}

// Interface for interacting with the OP (OpenID Provider)
type OpenIdProvider interface {
	Issuer() string
	RequestTokens(ctx context.Context, cicHash string) (*memguard.LockedBuffer, error)
	PublicKey(ctx context.Context, headers jws.Headers) (crypto.PublicKey, error)
	VerifyCICHash(ctx context.Context, idt []byte, expectedCICHash string) error
	VerifyNonGQSig(ctx context.Context, idt []byte, expectedNonce string) error
}

// Interface for interacting with the OP (OpenID Provider)
type BrowserOpenIdProvider interface {
	OpenIdProvider
	HookHTTPSession(h http.HandlerFunc)
}

func VerifyPKToken(ctx context.Context, pkt *pktoken.PKToken, provider OpenIdProvider) error {
	return PKTokenVerifier{
		AllowedProviders: []OpenIdProvider{provider},
	}.Verify(ctx, pkt)
}

type PKTokenVerifier struct {
	AllowedProviders []OpenIdProvider
	AllowedCosigners []CosignerProvider
}

func (v PKTokenVerifier) Verify(ctx context.Context, pkt *pktoken.PKToken) error {
	// If no providers (OPs) are set in the allowlist verify will always fail.
	if len(v.AllowedProviders) == 0 {
		return fmt.Errorf("no allowed providers (allowed OPs) set, you must set at least one provider")
	}

	var pktOp struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(pkt.Payload, &pktOp); err != nil {
		return err
	}

	//TODO: This function does not handle multiple providers with the same
	// issuer and different audiences. This does not handle the case where the
	// same provider (OP) is specified twice in an allowlist with different
	// audiences. Instead it will match on the first provider with the correct
	// issuer and then verify using that provider. If that provider has the
	// wrong audience it will throw an error even if there was a provider in
	// the allowlist that had both the correct audience and the correct issuer.
	// See https://github.com/openpubkey/openpubkey/issues/84
	var provider OpenIdProvider
	for _, allowedOp := range v.AllowedProviders {
		if allowedOp.Issuer() == pktOp.Issuer {
			provider = allowedOp
			break
		}
	}
	if provider == nil {
		return fmt.Errorf("the OP issuer (%s) in the PK Token is not an allowed issuer", pktOp.Issuer)
	}
	cic, err := pkt.GetCicValues()
	if err != nil {
		return err
	}

	commitment, err := cic.Hash()
	if err != nil {
		return err
	}

	idt, err := pkt.Compact(pkt.Op)
	if err != nil {
		return err
	}

	issuer, err := ExtractClaim(idt, "iss")
	if err != nil {
		return err
	}

	if issuer != provider.Issuer() {
		return fmt.Errorf("expected token to have issuer %s, got %s", provider.Issuer(), issuer)
	}

	alg, ok := pkt.ProviderAlgorithm()
	if !ok {
		return fmt.Errorf("provider algorithm type missing")
	}

	switch alg {
	case gq.GQ256:
		origHeadersB64, err := gq.OriginalJWTHeaders(idt)
		if err != nil {
			return err
		}

		origHeaders := jws.NewHeaders()
		err = parseJWTSegment(origHeadersB64, &origHeaders)
		if err != nil {
			return err
		}

		alg := origHeaders.Algorithm()
		if alg != jwa.RS256 {
			return fmt.Errorf("expected original headers to contain RS256 alg, got %s", alg)
		}

		// TODO: this needs to get the public key from a log of historic public keys based on the iat time in the token
		pubKey, err := provider.PublicKey(ctx, origHeaders)
		if err != nil {
			return fmt.Errorf("failed to get OP public key: %w", err)
		}

		rsaPubKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected public key to be a *rsa.PublicKey, got %T", pubKey)
		}

		err = pkt.VerifyGQSig(rsaPubKey, GQSecurityParameter)
		if err != nil {
			return fmt.Errorf("error verifying OP GQ signature on PK Token: %w", err)
		}

		err = provider.VerifyCICHash(ctx, idt, string(commitment))
		if err != nil {
			return fmt.Errorf("failed to verify CIC hash: %w", err)
		}
	case jwa.RS256:
		err = provider.VerifyNonGQSig(ctx, idt, string(commitment))
		if err != nil {
			if err == ErrNonGQUnsupported {
				return fmt.Errorf("oidc provider doesn't support non-GQ signatures")
			}
			return fmt.Errorf("failed to verify signature from OIDC provider: %w", err)
		}
	}

	err = pkt.VerifyCicSig()
	if err != nil {
		return fmt.Errorf("error verifying CIC signature on PK Token: %w", err)
	}

	// If no cosigner is set, then we don't require a cosigner.
	if len(v.AllowedCosigners) != 0 {
		if pkt.Cos == nil {
			return fmt.Errorf("cosigner required but no cosigner signature (COS) set in PK Token")
		}

		var cos *CosignerProvider
		if cosIss, ok := pkt.Cos.ProtectedHeaders().Get("iss"); !ok {
			return fmt.Errorf("no COS issuer set in the PK Token")
		} else {
			for _, allowedCos := range v.AllowedCosigners {
				if allowedCos.Issuer == cosIss {
					cos = &allowedCos
					break // Matching cosigner found on allowlist
				}
			}
			// if cos is nil, the PK Token's cosigner is not on the allowlist
			if cos == nil {
				return fmt.Errorf("the COS issuer (%s) in the PK Token is not an list of allowed issuers", cosIss)
			} else if err := pkt.VerifyCosSig(); err != nil {
				return fmt.Errorf("error verifying cosigner signature on PK Token: %w", err)
			}
		}
	}

	return nil
}

func DiscoverPublicKey(ctx context.Context, headers jws.Headers, issuer string) (crypto.PublicKey, error) {
	discConf, err := oidcclient.Discover(issuer, http.DefaultClient)
	if err != nil {
		return nil, fmt.Errorf("failed to call OIDC discovery endpoint: %w", err)
	}

	jwks, err := jwk.Fetch(ctx, discConf.JwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch to JWKS: %w", err)
	}

	kid := headers.KeyID()
	key, ok := jwks.LookupKeyID(kid)
	if !ok {
		return nil, fmt.Errorf("key %q isn't in JWKS", kid)
	}

	if key.Algorithm() != jwa.RS256 {
		return nil, fmt.Errorf("expected alg to be RS256 in JWK with kid %q for OP %q, got %q", kid, issuer, key.Algorithm())
	}

	pubKey := new(rsa.PublicKey)
	err = key.Raw(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	return pubKey, err
}

func ExtractClaim(idt []byte, claimName string) (string, error) {
	_, payloadB64, _, err := jws.SplitCompact(idt)
	if err != nil {
		return "", fmt.Errorf("failed to split/decode JWT: %w", err)
	}

	payload := make(map[string]any)
	err = parseJWTSegment(payloadB64, &payload)
	if err != nil {
		return "", err
	}

	claim, ok := payload[claimName]
	if !ok {
		return "", fmt.Errorf("claim '%s' missing from payload", claimName)
	}

	claimStr, ok := claim.(string)
	if !ok {
		return "", fmt.Errorf("expected claim '%s' to be a string, was %T", claimName, claim)
	}

	return claimStr, nil
}

func parseJWTSegment(segment []byte, v any) error {
	segmentJSON, err := util.Base64DecodeForJWT(segment)
	if err != nil {
		return fmt.Errorf("error decoding segment: %w", err)
	}

	err = json.Unmarshal(segmentJSON, v)
	if err != nil {
		return fmt.Errorf("error parsing segment: %w", err)
	}

	return nil
}
