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

package mocks

import (
	"context"
	"crypto"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/discover"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

func TestSimpleBackendOverride(t *testing.T) {

	issuer := "https://accounts.example.com/"
	mockBackend, err := NewMockProviderBackend(issuer, 3)
	require.NoError(t, err)

	expSigningKey, expKeyID, expRecord := mockBackend.RandomSigningKey()

	idTokenTemplate := IDTokenTemplate{
		CommitFunc:           AddAudCommit,
		Issuer:               issuer,
		Nonce:                "empty",
		NoNonce:              false,
		Aud:                  "also me",
		KeyID:                expKeyID,
		NoKeyID:              false,
		Alg:                  expRecord.Alg,
		NoAlg:                false,
		ExtraClaims:          map[string]any{"extraClaim": "extraClaimValue"},
		ExtraProtectedClaims: map[string]any{"extraHeader": "extraheaderValue"},
		SigningKey:           expSigningKey,
	}
	mockBackend.SetIDTokenTemplate(&idTokenTemplate)

	cicHash := util.Base64EncodeForJWT([]byte("0123456789ABCDEF0123456789ABCDEF"))
	tokens, err := mockBackend.RequestTokensOverrideFunc(string(cicHash))
	idt := tokens.IDToken
	require.NoError(t, err)
	require.NotNil(t, idt)

	record, err := mockBackend.GetPublicKeyFinder().ByToken(context.Background(), issuer, idt)
	require.NoError(t, err)

	payload, err := jws.Verify(idt, jws.WithKey(jwa.KeyAlgorithmFrom(record.Alg), record.PublicKey))
	require.NoError(t, err)
	require.Contains(t, string(payload), string(cicHash))
}

func TestKeySetCreatorsConvenience(t *testing.T) {
	issuer := "https://accounts.example.com/"
	skSet, recordSet, err := CreateRS256KeySet(issuer, 2)
	require.NoError(t, err)
	CheckKeySets(t, "Happy case: CreateRS256KeySet", issuer, "RS256", skSet, recordSet)

	skSet, recordSet, err = CreateES256KeySet(issuer, 2)
	require.NoError(t, err)
	CheckKeySets(t, "Happy case: CreateES256KeySet", issuer, "ES256", skSet, recordSet)
}

func TestKeySetCreators(t *testing.T) {
	issuerA := "https://accounts.example.com/"
	issuerB := "https://diff-accounts.example.com/"

	for numKeys := 1; numKeys < 3; numKeys++ {
		testCases := []struct {
			name     string
			issuer   string
			alg      string
			expError string
		}{
			{name: fmt.Sprintf("Happy case (RS256): %d key(s)", numKeys), issuer: issuerA, alg: "RS256",
				expError: "",
			},
			{name: fmt.Sprintf("Happy case (ES256): %d key(s)", numKeys), issuer: issuerB, alg: "ES256",
				expError: "",
			},
			{name: fmt.Sprintf("Unsupported alg (ZZ404): %d key(s)", numKeys), issuer: issuerB, alg: "ZZ404",
				expError: "unsupported alg",
			},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// skSet - set of signingKeys, recordSet - set of publicKeyRecords
				skSet, recordSet, err := CreateKeySet(tc.issuer, tc.alg, numKeys)
				if tc.expError != "" {
					require.ErrorContains(t, err, tc.expError, tc.name)
				} else {
					require.NoError(t, err, tc.name)
				}
				CheckKeySets(t, tc.name, tc.issuer, tc.alg, skSet, recordSet)
			})
		}
	}

}

func CheckKeySets(t *testing.T, name string, issuer string, alg string, skSet map[string]crypto.Signer, recordSet map[string]discover.PublicKeyRecord) {
	require.ElementsMatch(t, maps.Keys(skSet), maps.Keys(recordSet))
	for kid, signer := range skSet {
		record := recordSet[kid]
		require.NotNil(t, signer, name)
		require.NotNil(t, record, name)
		require.Equal(t, signer.Public(), record.PublicKey, name)
		require.Equal(t, issuer, record.Issuer, name)
		require.Equal(t, alg, record.Alg, name)
	}
}
