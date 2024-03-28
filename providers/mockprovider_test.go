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
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/providers/override"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestMockOpTableTest(t *testing.T) {
	issuer := githubIssuer
	providerOverride, err := override.NewMockProviderOverride(issuer, 2)
	require.NoError(t, err)

	SignGQ := false
	op := NewMockOp(SignGQ, providerOverride)

	cic := genCIC(t)
	expSigningKey, expKeyID, expRecord := providerOverride.RandomSigningKey()
	idTokenTemplate := override.IDTokenTemplate{
		Issuer:      issuer,
		Nonce:       "empty",
		NoNonce:     false,
		Aud:         "empty",
		KeyID:       expKeyID,
		NoKeyID:     false,
		Alg:         expRecord.Alg,
		NoAlg:       false,
		ExtraClaims: map[string]any{"sha": "c7d5b5ff9b2130a53526dcc44a1f69ef0e50d003"},
		SigningKey:  expSigningKey,
	}
	providerOverride.SetIDTokenTemplate(&idTokenTemplate)

	idToken, err := op.RequestTokens(context.TODO(), cic)
	require.NoError(t, err)
	require.NotNil(t, idToken)

	_, payloadB64, _, err := jws.SplitCompact(idToken)
	require.NoError(t, err)

	payload, err := util.Base64DecodeForJWT(payloadB64)
	require.NoError(t, err)

	payloadClaims := struct {
		Issuer   string `json:"iss"`
		Subject  string `json:"sub"`
		Audience string `json:"aud"`
		Nonce    string `json:"nonce,omitempty"`
	}{}
	err = json.Unmarshal(payload, &payloadClaims)
	require.NoError(t, err)
	pkRecord, err := op.PublicKeyByToken(context.Background(), idToken)
	require.NoError(t, err)

	// Check that GQ Signature verifies
	rsaKey, ok := pkRecord.PublicKey.(*rsa.PublicKey)

	require.True(t, ok)
	_, err = jws.Verify(idToken, jws.WithKey(jwa.RS256, rsaKey))
	require.NoError(t, err)
}
