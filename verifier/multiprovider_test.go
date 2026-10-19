// Copyright 2026 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package verifier_test

import (
	"context"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/jose"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/providers/mocks"
	"github.com/openpubkey/openpubkey/util"
	"github.com/openpubkey/openpubkey/verifier"
	"github.com/stretchr/testify/require"
)

const sharedIssuer = "https://shared-issuer.example"

// newNonceProvider returns a browser-style mock OP (nonce commitment, client ID
// enforced) for the shared issuer.
func newNonceProvider(t *testing.T, clientID string) (providers.OpenIdProvider, *mocks.MockProviderBackend) {
	t.Helper()
	op, backend, err := NewMockOpenIdProvider(false, sharedIssuer, "RS256", clientID, map[string]any{"aud": clientID})
	require.NoError(t, err)
	return op, backend
}

// newGQBoundProvider returns a CI/CD-style mock OP (GQ-bound commitment, client
// ID check skipped) for the shared issuer, whose tokens carry the given audience.
func newGQBoundProvider(t *testing.T, aud string) providers.OpenIdProvider {
	t.Helper()
	commitType := providers.CommitType{GQCommitment: true}
	op, _, idtTemplate, err := providers.NewMockProvider(providers.MockProviderOpts{
		Issuer:     sharedIssuer,
		Alg:        "RS256",
		ClientID:   "unused",
		GQSign:     true,
		NumKeys:    2,
		CommitType: commitType,
		VerifierOpts: providers.ProviderVerifierOpts{
			CommitType:        commitType,
			SkipClientIDCheck: true,
			GQOnly:            true,
		},
	})
	require.NoError(t, err)
	idtTemplate.Aud = aud
	return op
}

func authWith(t *testing.T, op providers.OpenIdProvider) *pktoken.PKToken {
	t.Helper()
	c, err := client.New(op)
	require.NoError(t, err)
	pkt, err := c.Auth(context.Background())
	require.NoError(t, err)
	return pkt
}

// bothOrders runs f with the verifiers registered in each order, since the
// outcome must not depend on registration order.
func bothOrders(t *testing.T, a, b verifier.ProviderVerifier, f func(t *testing.T, v *verifier.Verifier)) {
	t.Helper()
	for _, order := range [][]verifier.ProviderVerifier{{a, b}, {b, a}} {
		v, err := verifier.NewFromMany(order)
		require.NoError(t, err)
		f(t, v)
	}
}

func TestSameIssuer_TwoClientIDs(t *testing.T) {
	a, _ := newNonceProvider(t, "client-a")
	b, _ := newNonceProvider(t, "client-b")
	pktA := authWith(t, a)
	pktB := authWith(t, b)

	// The two mocks have different signing keys, so each token is accepted
	// by exactly one verifier and rejected by the other.
	bothOrders(t, a, b, func(t *testing.T, v *verifier.Verifier) {
		require.NoError(t, v.VerifyPKToken(context.Background(), pktA))
		require.NoError(t, v.VerifyPKToken(context.Background(), pktB))
	})
}

func TestSameIssuer_RejectedByAll(t *testing.T) {
	a, _ := newNonceProvider(t, "client-a")
	b, _ := newNonceProvider(t, "client-b")
	stranger, _ := newNonceProvider(t, "client-c")
	pktC := authWith(t, stranger)

	v, err := verifier.NewFromMany([]verifier.ProviderVerifier{a, b})
	require.NoError(t, err)
	err = v.VerifyPKToken(context.Background(), pktC)
	require.ErrorContains(t, err, "rejected by all 2 provider verifiers")
	require.ErrorContains(t, err, "client-a") // both underlying errors are reported
	require.ErrorContains(t, err, "client-b")
}

func TestSameIssuer_PerVerifierExpiration(t *testing.T) {
	a, backendA := newNonceProvider(t, "client-a")
	b, backendB := newNonceProvider(t, "client-b")
	// Both OPs issue already-expired ID tokens.
	backendA.IDTokenTemplate.ExtraClaims = map[string]any{"exp": 1}
	backendB.IDTokenTemplate.ExtraClaims = map[string]any{"exp": 1}
	pktA := authWith(t, a)
	pktB := authWith(t, b)

	never := verifier.ProviderVerifierExpires{ProviderVerifier: a, Expiration: verifier.ExpirationPolicies.NEVER_EXPIRE}
	oidc := verifier.ProviderVerifierExpires{ProviderVerifier: b, Expiration: verifier.ExpirationPolicies.OIDC}

	// The policy that applies is the accepting verifier's own.
	bothOrders(t, never, oidc, func(t *testing.T, v *verifier.Verifier) {
		require.NoError(t, v.VerifyPKToken(context.Background(), pktA), "client-a is NEVER_EXPIRE")
		err := v.VerifyPKToken(context.Background(), pktB)
		require.ErrorContains(t, err, "the ID token has expired (exp = 1)", "client-b is OIDC")
	})
}

func TestSameIssuer_BrowserAndCI(t *testing.T) {
	browser, _ := newNonceProvider(t, "client-a")
	ci := newGQBoundProvider(t, providers.AudPrefixForGQCommitment+"ci-job")
	pktBrowser := authWith(t, browser)
	pktCI := authWith(t, ci)

	bothOrders(t, browser, ci, func(t *testing.T, v *verifier.Verifier) {
		require.NoError(t, v.VerifyPKToken(context.Background(), pktBrowser))
		require.NoError(t, v.VerifyPKToken(context.Background(), pktCI))
	})
}

// impostorGQToken builds a PK Token whose ID Token is signed by the browser
// OP's real signing key and carries the browser app's client ID as its
// audience, but is GQ-bound rather than nonce-committed -- what a CI job
// could produce by setting `aud` to the browser client ID. The normal client
// refuses to mint such a token, so it is assembled by hand.
func impostorGQToken(t *testing.T, browser providers.OpenIdProvider, backend *mocks.MockProviderBackend, aud string) *pktoken.PKToken {
	t.Helper()
	signer, err := util.GenKeyPair(jose.ES256)
	require.NoError(t, err)
	jwkKey, err := jwk.PublicKeyOf(signer)
	require.NoError(t, err)
	require.NoError(t, jwkKey.Set(jwk.AlgorithmKey, jose.ES256))
	cic, err := clientinstance.NewClaims(jwkKey, map[string]any{})
	require.NoError(t, err)
	cicHash, err := cic.Hash()
	require.NoError(t, err)

	tmpl := *backend.IDTokenTemplate // same issuer, signing key and kid as the browser OP
	tmpl.CommitFunc = mocks.NoClaimCommit
	tmpl.Aud = aud
	tokens, err := tmpl.IssueTokens()
	require.NoError(t, err)
	gqToken, err := providers.CreateGQBoundToken(context.Background(), tokens.IDToken, browser, string(cicHash))
	require.NoError(t, err)

	cicToken, err := cic.Sign(signer, jose.ES256, gqToken)
	require.NoError(t, err)
	pkt, err := pktoken.New(gqToken, cicToken)
	require.NoError(t, err)
	return pkt
}

func TestSameIssuer_ImpostorRejectedByBoth(t *testing.T) {
	// Running several verifiers is only safe if each independently rejects
	// tokens not meant for it. A CI job can choose any audience, including
	// the browser app's client ID: the browser verifier must still reject
	// such a token on its commitment type, and the CI verifier must reject
	// it on the missing audience prefix.
	browser, backend := newNonceProvider(t, "client-a")
	impostor := impostorGQToken(t, browser, backend, "client-a")
	// A CI verifier for the same OP, trusting the same signing keys as the
	// browser verifier -- as GitLab and GitLab CI share keys in practice.
	ci := providers.NewProviderVerifier(sharedIssuer, providers.ProviderVerifierOpts{
		CommitType:        providers.CommitTypesEnum.GQ_BOUND,
		GQOnly:            true,
		SkipClientIDCheck: true,
		DiscoverPublicKey: &backend.PublicKeyFinder,
	})

	bothOrders(t, browser, ci, func(t *testing.T, v *verifier.Verifier) {
		err := v.VerifyPKToken(context.Background(), impostor)
		require.ErrorContains(t, err, "rejected by all 2 provider verifiers")
		require.ErrorContains(t, err, "commitment claim", "browser verifier: wrong commitment type")
		require.ErrorContains(t, err, "must be prefixed by", "CI verifier: audience lacks the GQ prefix")
	})
}
