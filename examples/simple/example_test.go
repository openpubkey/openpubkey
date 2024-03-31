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

package main

import (
	"testing"

	"github.com/openpubkey/openpubkey/providers"
	"github.com/stretchr/testify/require"
)

func TestGitlabExample(t *testing.T) {
	opOpts := providers.MockOpOpts{
		Issuer:              "mockIssuer",
		ClientID:            "mockClient-ID",
		SignGQ:              true,
		CommitmentClaimName: "nonce",
		VerifierOpts: providers.ProviderVerifierOpts{
			SkipClientIDCheck: false,
			GQOnly:            true,
			GQCommitment:      false,
			ClientID:          "mockClient-ID",
		},
	}
	op, _, _, err := providers.NewMockProvider(opOpts)
	require.NoError(t, err)

	pktJson, signedMsg, err := Sign(op)
	require.NoError(t, err)
	require.NotNil(t, pktJson)
	require.NotNil(t, signedMsg)

	err = Verify(op, pktJson, signedMsg)
	require.NoError(t, err)
}
