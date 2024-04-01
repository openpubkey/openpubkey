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
	"github.com/openpubkey/openpubkey/providers/mocks"
	"github.com/stretchr/testify/require"
)

func TestSimpleExample(t *testing.T) {
	providerOpts := mocks.MockProviderOpts{
		Issuer:          "mockIssuer",
		SignGQ:          true,
		CommitmentClaim: "aud",
		VerifierOpts: providers.ProviderVerifierOpts{
			CommitmentClaim:   "aud",
			SkipClientIDCheck: true,
			GQOnly:            true,
		},
	}

	op, _, _, err := mocks.NewMockProvider(providerOpts)
	require.NoError(t, err)

	err = login(op)
	require.NoError(t, err)
}
