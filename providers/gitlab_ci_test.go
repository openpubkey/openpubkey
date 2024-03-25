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
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/providers/discover"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestGitlabSimpleRequest(t *testing.T) {
	expProtected := []byte(`{"kid": "test-kid","typ": "JWT","alg": "RS256"}`)
	expPayload := []byte(`{"sha": "c7d5b5ff9b2130a53526dcc44a1f69ef0e50d003", "iat": 1710897326,"nbf": 1710897321,"exp": 1710900926,"sub": "project_path:openpubkey/gl-test:ref_type:branch:ref:main","aud": "OPENPUBKEY-PKTOKEN:1234"}`)

	protected := jws.NewHeaders()
	err := json.Unmarshal(expProtected, protected)
	require.NoError(t, err)

	algOp := jwa.RS256
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	expIdToken, err := jws.Sign(
		expPayload,
		jws.WithKey(
			algOp,
			signingKey,
			jws.WithProtectedHeaders(protected),
		),
	)
	require.NoError(t, err)

	jwksFunc, err := discover.MockGetJwksByIssuerOneKey(signingKey.Public(), "test-kid", string(algOp))
	require.NoError(t, err)

	op := &GitlabOp{
		issuer: gitlabIssuer,
		publicKeyFinder: discover.PublicKeyFinder{
			JwksFunc: jwksFunc,
		},
		getTokensFunc: func(envVarName string) (string, error) {
			return string(expIdToken), nil
		},
	}

	cic := genCIC(t)
	idToken, err := op.RequestTokens(context.Background(), cic)
	require.NoError(t, err)

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
	cicHash2, ok := headers.Get("cic")
	require.True(t, ok, "cic not found in GQ ID Token")

	require.Equal(t, string(cicHash), cicHash2, "cic hash in jwt header should match cic supplied")
}
