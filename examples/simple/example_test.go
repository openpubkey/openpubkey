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
	"github.com/openpubkey/openpubkey/providers/override"
	"github.com/stretchr/testify/require"
)

func TestGitlabExample(t *testing.T) {

	clientID := "mockClient-ID"
	CommitmentClaimName := "nonce"
	opOpts := providers.MockOpOpts{
		SignGQ:              true,
		ClaimCommitment:     true,
		CommitmentClaimName: CommitmentClaimName,
		VerifierOpts: providers.ProviderVerifierOpts{
			SkipClientIDCheck: false,
			GQOnly:            true,
			GQCommitment:      false,
			ClientID:          clientID,
		},
	}

	op, backend, err := providers.NewMockOpAndBackend(opOpts)
	require.NoError(t, err)

	expSigningKey, expKeyID, expRecord := backend.RandomSigningKey()
	idTokenTemplate := override.IDTokenTemplate{
		CommitmentType: &override.CommitmentType{
			ClaimCommitment: true,
			ClaimName:       CommitmentClaimName,
		},
		Issuer:     op.Issuer(),
		Nonce:      "empty",
		NoNonce:    false,
		Aud:        clientID,
		KeyID:      expKeyID,
		NoKeyID:    false,
		Alg:        expRecord.Alg,
		NoAlg:      false,
		SigningKey: expSigningKey,
	}
	backend.SetIDTokenTemplate(&idTokenTemplate)

	pktJson, signedMsg, err := Sign(op)
	require.NoError(t, err)
	require.NotNil(t, pktJson)
	require.NotNil(t, signedMsg)

	err = Verify(op, pktJson, signedMsg)
	require.NoError(t, err)
}
