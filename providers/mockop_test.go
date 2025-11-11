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
	"testing"

	"github.com/openpubkey/openpubkey/providers/mocks"
	"github.com/stretchr/testify/require"
)

func TestSimpleBackendOverride(t *testing.T) {
	clientId := "fake-client-id"

	googleOpOpts := GetDefaultGoogleOpOptions()
	issuer := googleOpOpts.Issuer
	googleOpOpts.ClientID = clientId

	opBackend, err := mocks.NewMockProviderBackend(issuer, "RS256", 2)
	require.NoError(t, err)

	expSigningKey, expKeyID, expRecord := opBackend.RandomSigningKey()

	idTokenTemplate := &mocks.IDTokenTemplate{
		CommitFunc:           mocks.AddNonceCommit,
		Issuer:               issuer,
		Nonce:                "empty",
		NoNonce:              false,
		Aud:                  clientId,
		KeyID:                expKeyID,
		NoKeyID:              false,
		Alg:                  expRecord.Alg,
		NoAlg:                false,
		ExtraClaims:          map[string]any{"extraClaim": "extraClaimValue"},
		ExtraProtectedClaims: map[string]any{"extraHeader": "extraheaderValue"},
		SigningKey:           expSigningKey,
	}

	idp, err := mocks.NewMockOp(issuer, idTokenTemplate, opBackend)
	require.NoError(t, err)
	require.NotNil(t, idp)

	rt := idp.GetHTTPClient()
	require.NotNil(t, rt)
	googleOpOpts.HttpClient = rt
	googleOpOpts.OpenBrowser = false

	op := NewGoogleOpWithOptions(googleOpOpts)

	browserWindowHook := idp.GetUserAuthCompleteSignal()
	op.ReuseBrowserWindowHook(browserWindowHook)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		err := idp.Run(ctx)
		require.NoError(t, err)
	}()

	cic := GenCIC(t)
	require.NotNil(t, cic)

	tokens, err := op.RequestTokens(ctx, cic)
	require.NoError(t, err)
	idToken := tokens.IDToken
	require.NotNil(t, idToken)
}
