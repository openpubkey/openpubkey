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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestGithubOpSimpleRequest(t *testing.T) {
	expCicHash := "LJJfahE5cC1AgAWrMkUDL85d0oSSBcP6FJVSulzojds"

	// Setup expected test data
	expProtected := []byte(`{"alg":"RS256","kid":"1F2AB83404C08EC9EA0BB99DAED02186B091DBF4","typ":"JWT","x5t":"Hyq4NATAjsnqC7mdrtAhhrCR2_Q"}`)
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

	// Lowercase requestTokens just gets the ID Token
	idTokenLB, err := op.requestTokens(context.TODO(), expCicHash)
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

func TestGithubOpFullGQ(t *testing.T) {
	cic := NewCIC(t)

	// Setup expected test data
	expProtected := []byte(`{"alg":"RS256","kid":"1F2AB83404C08EC9EA0BB99DAED02186B091DBF4","typ":"JWT","x5t":"Hyq4NATAjsnqC7mdrtAhhrCR2_Q"}`)
	expPayload := []byte(`{"sub":"repo:example/fake:ref:refs/heads/main","aud":"LJJfahE5cC1AgAWrMkUDL85d0oSSBcP6FJVSulzojds","ref":"refs/heads/main","sha":\"353722c917a3f94988b826b82405ca05feddb1fe","repository":"example/fake","repository_owner":"fakeowner","iss":"https://token.actions.githubusercontent.com","nbf":1709839869,"exp":1709840769,"iat":1709840469}`)

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

	expResponseBody := fmt.Sprintf(`{"count":1857,"value":"%s"}`, expIdToken)

	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(http.StatusOK)
		res.Write([]byte(expResponseBody))
	}))
	defer func() { testServer.Close() }()

	tokenRequestURL := testServer.URL
	authToken := "fakeAuthToken"
	op := NewGithubOp(tokenRequestURL, authToken)

	idToken, err := op.RequestTokens(context.TODO(), cic)
	require.NoError(t, err)
	require.NotNil(t, idToken)

	_, payloadB64, _, err := jws.SplitCompact(idToken)
	require.NoError(t, err)

	origHeadersB64, err := gq.OriginalJWTHeaders(idToken)
	require.NoError(t, err)
	origHeaders, err := util.Base64DecodeForJWT(origHeadersB64)
	require.NoError(t, err)
	require.Equal(t, string(expProtected), string(origHeaders))

	payload, err := util.Base64DecodeForJWT(payloadB64)
	require.NoError(t, err)
	require.Equal(t, string(expPayload), string(payload))

}

// Simple test to ensure we don't accidentally break this simple function
func TestBuildTokenURL(t *testing.T) {
	TokenRequestURL := "http://example.com/token-request"
	audience := "fakeAudience"

	tokenURL, err := buildTokenURL(TokenRequestURL, audience)
	require.NoError(t, err)
	require.Equal(t, "http://example.com/token-request?audience=fakeAudience", tokenURL)
}

func NewCIC(t *testing.T) *clientinstance.Claims {
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	require.NoError(t, err)
	jwkKey, err := jwk.PublicKeyOf(signer)
	require.NoError(t, err)
	err = jwkKey.Set(jwk.AlgorithmKey, alg)
	require.NoError(t, err)
	cic, err := clientinstance.NewClaims(jwkKey, map[string]any{})
	require.NoError(t, err)
	return cic
}
