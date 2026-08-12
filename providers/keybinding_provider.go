// Copyright 2025 OpenPubkey
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

package providers

import (
	"context"
	"crypto"
	"fmt"

	simpleoidc "github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// KeyBindingOp configures standardOp to use the OIDC key binding protocol as described in the
// draft standard "OpenID Connect Key Binding" at https://openid.github.io/connect-key-binding/main.html
type KeyBindingOp struct {
	StandardOp
}

// ConfigKeyBinding sets up the KeyBindingOp to use the provided signer and algorithm.
// This is required to successfully use this type of OP.
func (s *KeyBindingOp) ConfigKeyBinding(kbSigner crypto.Signer, kbAlg string) error {
	if kbSigner == nil {
		return fmt.Errorf("key binding signer must not be nil")
	}
	s.keyBindingSigner = kbSigner
	s.keyBindingSignerAlg = kbAlg
	return nil
}

func (s *KeyBindingOp) VerifyIDToken(ctx context.Context, idt []byte, cic *clientinstance.Claims) error {
	vp := NewProviderVerifier(
		s.issuer,
		ProviderVerifierOpts{
			CommitType:        CommitTypesEnum.KEY_BOUND,
			ClientID:          s.clientID,
			DiscoverPublicKey: &s.publicKeyFinder,
		})
	return vp.VerifyIDToken(ctx, idt, cic)
}

// KeyBindingOpRefreshable extends KeyBindingOp to support a refresh flow
type KeyBindingOpRefreshable struct {
	KeyBindingOp
}

func (r *KeyBindingOpRefreshable) RefreshTokens(ctx context.Context, refreshToken []byte) (*simpleoidc.Tokens, error) {
	return r.refreshTokens(ctx, refreshToken)
}

func (r *KeyBindingOpRefreshable) VerifyRefreshedIDToken(ctx context.Context, origIdt []byte, reIdt []byte) error {
	if err := simpleoidc.SameIdentity(origIdt, reIdt); err != nil {
		return fmt.Errorf("refreshed ID Token is for different subject than original ID Token: %w", err)
	}
	if err := simpleoidc.RequireOlder(origIdt, reIdt); err != nil {
		return fmt.Errorf("refreshed ID Token should not be issued before original ID Token: %w", err)
	}
	// The key binding is carried in the cnf claim, not in a CIC commitment. So
	// proving the refreshed token is bound to the same key as the original is
	// done by comparing cnf claims (by JWK thumbprint).
	if err := simpleoidc.SameCnfThumbprint(origIdt, reIdt); err != nil {
		return fmt.Errorf("refreshed ID Token has different cnf claim (key binding) than original ID Token: %w", err)
	}

	reJwt, err := simpleoidc.NewJwt(reIdt)
	if err != nil {
		return fmt.Errorf("error parsing refreshed ID token: %w", err)
	}
	if typ := reJwt.GetSignature().GetProtectedClaims().Type; typ != KEYBOUND_TYP {
		return fmt.Errorf("expected key-bound refreshed ID Token (typ=%s) but got typ=%s", KEYBOUND_TYP, typ)
	}

	// Verify the OP's signature on the refreshed ID Token, mirroring the
	// StandardOp refresh verification (StandardOpRefreshable.VerifyRefreshedIDToken).
	options := []rp.Option{}
	if r.HttpClient != nil {
		options = append(options, rp.WithHTTPClient(r.HttpClient))
	}
	// The redirect URI is not used when verifying a refreshed token.
	redirectURI := ""
	relyingParty, err := rp.NewRelyingPartyOIDC(ctx, r.issuer, r.clientID,
		r.ClientSecret, redirectURI, r.Scopes, options...)
	if err != nil {
		return fmt.Errorf("failed to create RP to verify token: %w", err)
	}
	if _, err := rp.VerifyIDToken[*oidc.IDTokenClaims](ctx, string(reIdt), relyingParty.IDTokenVerifier()); err != nil {
		return err
	}
	return nil
}

var _ RefreshableOpenIdProvider = (*KeyBindingOpRefreshable)(nil)
