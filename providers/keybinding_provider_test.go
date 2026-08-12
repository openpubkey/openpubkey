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
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/openpubkey/openpubkey/providers/mocks"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func keyBindingTestJWK(t *testing.T, signer crypto.Signer, alg string) jwk.Key {
	t.Helper()
	jwkKey, err := jwk.PublicKeyOf(signer.Public())
	require.NoError(t, err)
	require.NoError(t, jwkKey.Set(jwk.AlgorithmKey, alg))
	return jwkKey
}

func TestKeyBindingProvider(t *testing.T) {
	// This isn't a great test because it doesn't test the client to OP interaction.
	// It will detect if someone changes ConfigKeyBinding so it returns an error
	issuer := helloIssuer
	providerOverride, err := mocks.NewMockProviderBackend(issuer, "RS256", 2)
	require.NoError(t, err)

	op := &KeyBindingOp{
		StandardOp: StandardOp{
			clientID:                  "also me",
			issuer:                    issuer,
			publicKeyFinder:           providerOverride.PublicKeyFinder,
			requestTokensOverrideFunc: providerOverride.RequestTokensOverrideFunc,
		},
	}

	cic, signer, alg := GenCICDeterministic(t, map[string]any{})
	jwkKey := keyBindingTestJWK(t, signer, alg)

	expSigningKey, expKeyID, expRecord := providerOverride.RandomSigningKey()

	idTokenTemplate := mocks.IDTokenTemplate{
		CommitFunc: mocks.AddNonceCommit,
		Issuer:     issuer,
		Nonce:      "empty",
		NoNonce:    false,
		Aud:        "also me",
		KeyID:      expKeyID,
		NoKeyID:    false,
		Alg:        expRecord.Alg,
		NoAlg:      false,
		ExtraClaims: map[string]any{
			"cnf": map[string]any{
				"jwk": jwkKey,
			},
		},
		ExtraProtectedClaims: map[string]any{
			"typ": KEYBOUND_TYP,
		},
		SigningKey: expSigningKey,
	}
	providerOverride.SetIDTokenTemplate(&idTokenTemplate)

	err = op.ConfigKeyBinding(signer, alg)
	require.NoError(t, err)

	tokens, err := op.RequestTokens(context.Background(), cic)
	require.NoError(t, err)

	_, payloadB64, _, err := jws.SplitCompact(tokens.IDToken)
	require.NoError(t, err)

	payload, err := util.Base64DecodeForJWT(payloadB64)
	require.NoError(t, err)

	type payloadCnf struct {
		Jwk json.RawMessage `json:"jwk"`
	}
	payloadClaims := struct {
		Cnf payloadCnf `json:"cnf"`
	}{}
	err = json.Unmarshal(payload, &payloadClaims)
	require.NoError(t, err)

	jwkKeyJson, err := json.Marshal(jwkKey)
	require.NoError(t, err)
	require.Equal(t, string(jwkKeyJson), string(payloadClaims.Cnf.Jwk))

	require.Equal(t, "mock-refresh-token", string(tokens.RefreshToken))
	require.Equal(t, "mock-access-token", string(tokens.AccessToken))

	err = op.VerifyIDToken(context.Background(), tokens.IDToken, cic)
	require.NoError(t, err)
}

// TestVerifyRefreshedIDTokenRequiresKeyBoundTyp ensures VerifyRefreshedIDToken
// rejects a refreshed ID Token that is not marked key-bound via the "typ"
// header (KEYBOUND_TYP), even when subject and cnf key binding still match.
func TestVerifyRefreshedIDTokenRequiresKeyBoundTyp(t *testing.T) {
	issuer := helloIssuer
	providerOverride, err := mocks.NewMockProviderBackend(issuer, "RS256", 2)
	require.NoError(t, err)

	_, signer, alg := GenCICDeterministic(t, map[string]any{})
	jwkKey := keyBindingTestJWK(t, signer, alg)

	expSigningKey, expKeyID, expRecord := providerOverride.RandomSigningKey()

	// Both tokens share the same subject and cnf key binding, so SameIdentity,
	// RequireOlder, and SameCnfThumbprint all pass and the typ check is what
	// decides the outcome.
	base := mocks.IDTokenTemplate{
		CommitFunc: mocks.AddNonceCommit,
		Issuer:     issuer,
		Nonce:      "empty",
		Aud:        "also me",
		KeyID:      expKeyID,
		Alg:        expRecord.Alg,
		ExtraClaims: map[string]any{
			"cnf": map[string]any{"jwk": jwkKey},
		},
		SigningKey: expSigningKey,
	}

	// Original token IS key-bound (typ = dpop+id_token).
	origTmpl := base
	origTmpl.ExtraProtectedClaims = map[string]any{"typ": KEYBOUND_TYP}
	origTokens, err := origTmpl.IssueTokens()
	require.NoError(t, err)

	// Refreshed token is NOT key-bound: no typ override, so it defaults to "JWT".
	reTmpl := base
	reTokens, err := reTmpl.IssueTokens()
	require.NoError(t, err)

	op := &KeyBindingOpRefreshable{}
	err = op.VerifyRefreshedIDToken(context.Background(), origTokens.IDToken, reTokens.IDToken)
	require.ErrorContains(t, err, "expected key-bound refreshed ID Token")
}
