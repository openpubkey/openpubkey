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

package providers

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/openpubkey/openpubkey/providers/mocks"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestGitlabSimpleRequest(t *testing.T) {

	issuer := gitlabIssuer
	providerOverride, err := mocks.NewMockProviderBackend(issuer, "RS256", 2)
	require.NoError(t, err)

	op := &GitlabCiOp{
		issuer:                    gitlabIssuer,
		publicKeyFinder:           providerOverride.PublicKeyFinder,
		requestTokensOverrideFunc: providerOverride.RequestTokensOverrideFunc,
	}

	aud := AudPrefixForGQCommitment
	cic := GenCIC(t)

	expSigningKey, expKeyID, expRecord := providerOverride.RandomSigningKey()
	idTokenTemplate := mocks.IDTokenTemplate{
		CommitFunc:  mocks.NoClaimCommit,
		Issuer:      issuer,
		Nonce:       "empty",
		NoNonce:     false,
		Aud:         aud,
		KeyID:       expKeyID,
		NoKeyID:     false,
		Alg:         expRecord.Alg,
		NoAlg:       false,
		ExtraClaims: map[string]any{"sha": "c7d5b5ff9b2130a53526dcc44a1f69ef0e50d003"},
		SigningKey:  expSigningKey,
	}
	providerOverride.SetIDTokenTemplate(&idTokenTemplate)

	tokens, err := op.RequestTokens(context.Background(), cic)
	require.NoError(t, err)
	idToken := tokens.IDToken

	cicHash, err := cic.Hash()
	require.NoError(t, err)
	require.NotNil(t, cicHash)

	headerB64, _, _, err := jws.SplitCompact(idToken)
	require.NoError(t, err)
	headerJson, err := util.Base64DecodeForJWT(headerB64)
	require.NoError(t, err)
	headers := jws.NewHeaders()
	err = json.Unmarshal(headerJson, &headers)
	require.NoError(t, err)
	var cicHash2 string
	err = headers.Get("cic", &cicHash2)
	require.NoError(t, err)

	require.Equal(t, string(cicHash), cicHash2, "cic hash in jwt header should match cic supplied")
}
