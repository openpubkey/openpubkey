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

package mocks

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMockOp(t *testing.T) {
	issuer := "https://issuer.example.com"
	clientId := "test-client-id"

	idp, err := NewMockOp(issuer, []Subject{
		Subject{
			SubjectID: "alice@example.com",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, idp)

	expSigningKey, expKeyID, expRecord := idp.RandomSigningKey()
	idp.MockProviderBackend.IDTokenTemplate = &IDTokenTemplate{
		CommitFunc: AddNonceCommit,
		Issuer:     issuer,
		Nonce:      "empty",
		NoNonce:    false,
		Aud:        clientId,
		KeyID:      expKeyID,
		NoKeyID:    false,
		Alg:        expRecord.Alg,
		NoAlg:      false,
		SigningKey: expSigningKey,
	}

	rt := idp.GetHTTPClient()
	require.NotNil(t, rt)
	require.Contains(t, idp.CreateAuthCode("test-nonce"), "fake-auth-code-")

	// TODO: Expand these smoke tests
}
