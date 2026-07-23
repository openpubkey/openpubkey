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

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/openpubkey/openpubkey/cosigner/msgs"
	"github.com/openpubkey/openpubkey/jose"
	pktokenmocks "github.com/openpubkey/openpubkey/pktoken/mocks"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestCosSimple(t *testing.T) {
	cosP := CosignerProvider{
		Issuer:       "https://example.com",
		CallbackPath: "/mfaredirect",
	}
	redirectURI := fmt.Sprintf("%s/%s", "http://localhost:5555", cosP.CallbackPath)

	initAuthSig, nonce, err := cosP.CreateInitAuthSig(redirectURI)
	require.NotNil(t, initAuthSig)
	require.NotNil(t, nonce)
	require.NoError(t, err)

	pktJson := []byte("fake pkt bytes")
	sig1 := []byte("fake signature one bytes")
	authUri, err := cosP.initAuthURI(pktJson, sig1)
	require.NotNil(t, authUri)
	require.Equal(t, "https://example.com/mfa-auth-init?pkt=ZmFrZSBwa3QgYnl0ZXM&sig1=fake+signature+one+bytes", authUri)
	require.NoError(t, err)

	sig2 := []byte("fake signature two bytes")
	authCodeUri, err := cosP.authcodeURI(sig2)
	require.NotNil(t, authCodeUri)
	require.Equal(t, "https://example.com/sign?sig2=fake+signature+two+bytes", authCodeUri)
	require.NoError(t, err)
}

func TestCosignerAuthWaitTimeoutClosesServerAndCancelsHandler(t *testing.T) {
	signRequestStarted := make(chan struct{})
	signRequestCanceled := make(chan struct{})
	cosignerServer := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(signRequestStarted)
		<-r.Context().Done()
		close(signRequestCanceled)
	}))
	defer cosignerServer.Close()

	signer, err := util.GenKeyPair(jose.ES256)
	require.NoError(t, err)
	pkt, err := pktokenmocks.GenerateMockPKToken(t, signer, jose.ES256)
	require.NoError(t, err)

	cosignerProvider := CosignerProvider{
		Issuer:          cosignerServer.URL,
		CallbackPath:    "/mfaredirect",
		AuthWaitTimeout: 500 * time.Millisecond,
	}
	redirectCh := make(chan string, 1)
	resultCh := make(chan error, 1)
	go func() {
		_, requestErr := cosignerProvider.RequestToken(context.Background(), signer, pkt, redirectCh)
		resultCh <- requestErr
	}()

	callbackURI := callbackURIFromCosignerRedirect(t, <-redirectCh)
	callbackDone := make(chan error, 1)
	go func() {
		response, callbackErr := http.Get(callbackURI + "?authcode=test-authcode")
		if response != nil {
			_ = response.Body.Close()
		}
		callbackDone <- callbackErr
	}()

	select {
	case <-signRequestStarted:
	case <-time.After(time.Second):
		t.Fatal("cosigner signature request did not start")
	}

	select {
	case err := <-resultCh:
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.Contains(t, err.Error(), "authentication timed out after waiting 500ms")
	case <-time.After(2 * time.Second):
		t.Fatal("RequestToken did not return after its authentication timeout")
	}

	select {
	case <-signRequestCanceled:
	case <-time.After(time.Second):
		t.Fatal("closing the callback server did not cancel its active handler")
	}
	require.Error(t, <-callbackDone)

	parsedCallbackURI, err := url.Parse(callbackURI)
	require.NoError(t, err)
	connection, err := net.DialTimeout("tcp", parsedCallbackURI.Host, 100*time.Millisecond)
	if connection != nil {
		_ = connection.Close()
	}
	require.Error(t, err, "cosigner callback listener is still accepting connections")
}

func TestCosignerAuthWaitTimeoutIncludesRedirectHandoff(t *testing.T) {
	signer, err := util.GenKeyPair(jose.ES256)
	require.NoError(t, err)
	pkt, err := pktokenmocks.GenerateMockPKToken(t, signer, jose.ES256)
	require.NoError(t, err)

	cosignerProvider := CosignerProvider{
		Issuer:          "https://example.com",
		CallbackPath:    "/mfaredirect",
		AuthWaitTimeout: 30 * time.Millisecond,
	}
	started := time.Now()
	result, err := cosignerProvider.RequestToken(
		context.Background(), signer, pkt, make(chan string),
	)
	require.Nil(t, result)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Contains(t, err.Error(), "authentication timed out after waiting 30ms")
	require.Less(t, time.Since(started), time.Second)
}

func callbackURIFromCosignerRedirect(t *testing.T, redirect string) string {
	t.Helper()
	redirectURI, err := url.Parse(redirect)
	require.NoError(t, err)
	message, err := jws.Parse([]byte(redirectURI.Query().Get("sig1")))
	require.NoError(t, err)
	var initAuth msgs.InitMFAAuth
	require.NoError(t, json.Unmarshal(message.Payload(), &initAuth))
	return initAuth.RedirectUri
}
