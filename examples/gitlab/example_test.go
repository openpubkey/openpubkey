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

package gitlab_example

import (
	"testing"

	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/providers/override"
	"github.com/stretchr/testify/require"
)

func TestGitlabExample(t *testing.T) {
	SignGQ := true

	opOpts := providers.MockOpOpts{
		SignGQ:       SignGQ,
		GQCommitment: true,
		VerifierOpts: providers.ProviderVerifierOpts{
			SkipClientIDCheck: true,
			GQOnly:            true,
			GQCommitment:      true,
		},
	}

	op, backend, err := providers.NewMockOpAndBackend(opOpts)
	require.NoError(t, err)

	expSigningKey, expKeyID, expRecord := backend.RandomSigningKey()
	idTokenTemplate := override.IDTokenTemplate{
		CommitmentType: &override.CommitmentType{
			ClaimCommitment: false,
		},
		Issuer:      op.Issuer(),
		Nonce:       "empty",
		NoNonce:     false,
		Aud:         providers.AudPrefixForGQCommitment,
		KeyID:       expKeyID,
		NoKeyID:     false,
		Alg:         expRecord.Alg,
		NoAlg:       false,
		ExtraClaims: map[string]any{"sha": "c7d5b5ff9b2130a53526dcc44a1f69ef0e50d003"},
		SigningKey:  expSigningKey,
	}
	backend.SetIDTokenTemplate(&idTokenTemplate)

	opts := Opts{
		altOp: op,
	}

	err = SignWithGitlab(opts)
	require.NoError(t, err)
}
