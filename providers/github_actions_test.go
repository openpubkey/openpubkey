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
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/discover"
	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/providers/mocks"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestGithubOpTableTest(t *testing.T) {
	issuer := githubIssuer
	providerOverride, err := mocks.NewMockProviderBackend(issuer, 2)
	require.NoError(t, err)

	op := &GithubOp{
		issuer:                    githubIssuer,
		rawTokenRequestURL:        "fakeTokenURL",
		tokenRequestAuthToken:     "fakeToken",
		publicKeyFinder:           providerOverride.PublicKeyFinder,
		requestTokensOverrideFunc: providerOverride.RequestTokensOverrideFunc,
	}

	cic := GenCIC(t)
	expSigningKey, expKeyID, expRecord := providerOverride.RandomSigningKey()
	idTokenTemplate := mocks.IDTokenTemplate{
		CommitFunc:  mocks.AddAudCommit,
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

	tokens, err := op.RequestTokens(context.Background(), cic)
	require.NoError(t, err)
	idToken := tokens.IDToken
	require.NotNil(t, idToken)

	_, payloadB64, _, err := jws.SplitCompact(idToken)
	require.NoError(t, err)

	headers := extractHeaders(t, idToken)
	require.Equal(t, gq.GQ256, headers.Algorithm(), "github must only return GQ signed ID Tokens but we got (%s)", headers.Algorithm())

	origHeadersB64, err := gq.OriginalJWTHeaders(idToken)
	require.NoError(t, err)
	origHeaders, err := util.Base64DecodeForJWT(origHeadersB64)
	require.NoError(t, err)
	require.Contains(t, string(origHeaders), "RS256")

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
	ok, err = gq.GQ256VerifyJWT(rsaKey, idToken)
	require.NoError(t, err)
	require.True(t, ok)
}

// These two tests are regression tests for  deserialization bug
// that broke our ability to read the ID Token directly from the HTTP
// response. To ensure we don't break this again this test stands up a server
// so that all of the RequestToken code is tested. For all the other tests
// we just use the standard override functions.
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
		_, err := res.Write([]byte(expResponseBody))
		require.NoError(t, err)
	}))
	defer func() { testServer.Close() }()

	tokenRequestURL := testServer.URL
	authToken := "fakeAuthToken"
	op := NewGithubOp(tokenRequestURL, authToken)

	// Lowercase requestTokens just gets the ID Token (no GQ signing or modification)
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

	cic := GenCIC(t)

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
		_, err := res.Write([]byte(expResponseBody))
		require.NoError(t, err)
	}))
	defer func() { testServer.Close() }()

	tokenRequestURL := testServer.URL
	authToken := "fakeAuthToken"

	jwksFunc, err := discover.MockGetJwksByIssuerOneKey(signingKey.Public(), "1F2AB83404C08EC9EA0BB99DAED02186B091DBF4", string(algOp))
	require.NoError(t, err)

	op := &GithubOp{
		rawTokenRequestURL:    tokenRequestURL,
		tokenRequestAuthToken: authToken,
		publicKeyFinder: discover.PublicKeyFinder{
			JwksFunc: jwksFunc,
		},
	}

	tokens, err := op.RequestTokens(context.Background(), cic)
	require.NoError(t, err)
	idToken := tokens.IDToken
	require.NotNil(t, idToken)

	_, payloadB64, _, err := jws.SplitCompact(idToken)
	require.NoError(t, err)

	headers := extractHeaders(t, idToken)
	require.Equal(t, gq.GQ256, headers.Algorithm(), "github must only return GQ signed ID Tokens but we got (%s)", headers.Algorithm())

	origHeadersB64, err := gq.OriginalJWTHeaders(idToken)
	require.NoError(t, err)
	origHeaders, err := util.Base64DecodeForJWT(origHeadersB64)
	require.NoError(t, err)
	require.Equal(t, string(expProtected), string(origHeaders))

	payload, err := util.Base64DecodeForJWT(payloadB64)
	require.NoError(t, err)
	require.Equal(t, string(expPayload), string(payload))

	// Check that GQ Signature verifies
	rsaKey, ok := signingKey.Public().(*rsa.PublicKey)
	require.True(t, ok)
	ok, err = gq.GQ256VerifyJWT(rsaKey, idToken)
	require.NoError(t, err)
	require.True(t, ok)
}

// Simple test to ensure we don't accidentally break this simple function
func TestBuildTokenURL(t *testing.T) {
	TokenRequestURL := "http://example.com/token-request"
	audience := "fakeAudience"

	tokenURL, err := buildTokenURL(TokenRequestURL, audience)
	require.NoError(t, err)
	require.Equal(t, "http://example.com/token-request?audience=fakeAudience", tokenURL)
}

func extractHeaders(t *testing.T, idToken []byte) jws.Headers {
	headersB64, _, _, err := jws.SplitCompact(idToken)
	require.NoError(t, err)
	headersJson, err := util.Base64DecodeForJWT(headersB64)
	require.NoError(t, err)
	headers := jws.NewHeaders()
	err = json.Unmarshal(headersJson, &headers)
	require.NoError(t, err)
	return headers
}
