// Copyright 2026 OpenPubkey
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

package github_actions_example

import (
	"testing"

	"github.com/openpubkey/openpubkey/providers"
	"github.com/stretchr/testify/require"
)

func TestGithubActionsExample(t *testing.T) {
	providerOpts := providers.MockProviderOpts{
		Issuer:     "https://token.actions.githubusercontent.com",
		ClientID:   "test_client_id",
		GQSign:     true,
		NumKeys:    2,
		CommitType: providers.CommitTypesEnum.AUD_CLAIM,
		VerifierOpts: providers.ProviderVerifierOpts{
			SkipClientIDCheck: true,
			GQOnly:            true,
			CommitType:        providers.CommitTypesEnum.AUD_CLAIM,
		},
	}
	op, _, _, err := providers.NewMockProvider(providerOpts)
	require.NoError(t, err)

	opts := Opts{
		altOp: op,
	}

	err = SignWithGithubActions(opts)
	require.NoError(t, err)
}
