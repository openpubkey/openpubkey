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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestGithubOp(t *testing.T) {
	expCicHash := "LJJfahE5cC1AgAWrMkUDL85d0oSSBcP6FJVSulzojds"

	// Setup expected test data
	expProtected := []byte(`{"typ":"JWT","alg":"RS256","x5t":"Hyq4NATAjsnqC7mdrtAhhrCR2_Q","kid":"1F2AB83404C08EC9EA0BB99DAED02186B091DBF4"}`)
	expPayload := []byte(`{"sub":"repo:example/fake:ref:refs/heads/main","aud":"LJJfahE5cC1AgAWrMkUDL85d0oSSBcP6FJVSulzojds","ref":"refs/heads/main","sha":\"353722c917a3f94988b826b82405ca05feddb1fe","repository":"example/fake","repository_owner":"fakeowner","iss":"https://token.actions.githubusercontent.com","nbf":1709839869,"exp":1709840769,"iat":1709840469}`)
	expSig := []byte(`fakesig`)
	expIdToken := string(util.Base64EncodeForJWT(expProtected)) + "." + string(util.Base64EncodeForJWT(expPayload)) + "." + string(util.Base64EncodeForJWT(expSig))
	expResponseBody := fmt.Sprintf(`{"count":1857,"value":"%s"}`, expIdToken)

	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(http.StatusOK)
		res.Write([]byte(expResponseBody))
	}))
	defer func() { testServer.Close() }()

	tokenRequestURL := testServer.URL
	authToken := "fakeAuthToken"
	op := NewGithubOp(tokenRequestURL, authToken)

	idTokenLB, err := op.RequestTokens(context.TODO(), expCicHash)
	require.NoError(t, err)
	require.NotNil(t, idTokenLB)

	idToken := make([]byte, len(idTokenLB.Bytes()))
	copy(idToken, idTokenLB.Bytes())

	headerB64, payloadB64, sigB64, err := jws.SplitCompact(idToken)
	require.NoError(t, err)

	header, err := util.Base64DecodeForJWT(headerB64)
	require.NoError(t, err)
	require.Equal(t, string(expProtected), string(header))

	payload, err := util.Base64DecodeForJWT(payloadB64)
	require.NoError(t, err)
	require.Equal(t, string(expPayload), string(payload))

	sig, err := util.Base64DecodeForJWT(sigB64)
	require.NoError(t, err)
	require.Equal(t, string(expSig), string(sig))

	// Finally check the ID Token we get matches the ID Token we gave
	require.Equal(t, string(expIdToken), string(idToken))
}

// Simple test to ensure we don't accidentally break this simple function
func TestBuildTokenURL(t *testing.T) {
	TokenRequestURL := "http://example.com/token-request"
	audience := "fakeAudience"

	tokenURL, err := buildTokenURL(TokenRequestURL, audience)
	require.NoError(t, err)
	require.Equal(t, "http://example.com/token-request?audience=fakeAudience", tokenURL)
}
