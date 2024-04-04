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
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/providers/mocks"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestGoogleSimpleRequest(t *testing.T) {
	gqSign := false

	issuer := googleIssuer
	providerOverride, err := mocks.NewMockProviderBackend(issuer, 2)
	require.NoError(t, err)

	op := &GoogleOp{
		issuer:                   googleIssuer,
		publicKeyFinder:          providerOverride.PublicKeyFinder,
		requestTokenOverrideFunc: providerOverride.RequestTokenOverrideFunc,
	}

	cic := GenCIC(t)
	expSigningKey, expKeyID, expRecord := providerOverride.RandomSigningKey()

	idTokenTemplate := mocks.IDTokenTemplate{
		CommitFunc:           mocks.AddNonceCommit,
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
	providerOverride.SetIDTokenTemplate(&idTokenTemplate)

	idToken, err := op.RequestTokens(context.Background(), cic)
	require.NoError(t, err)

	cicHash, err := cic.Hash()
	require.NoError(t, err)
	require.NotNil(t, cicHash)

	headerB64, payloadB64, _, err := jws.SplitCompact(idToken)
	require.NoError(t, err)
	headerJson, err := util.Base64DecodeForJWT(headerB64)
	require.NoError(t, err)

	if gqSign {
		headers := jws.NewHeaders()
		err = json.Unmarshal(headerJson, &headers)
		require.NoError(t, err)
		cicHash2, ok := headers.Get("cic")
		require.True(t, ok, "cic not found in GQ ID Token")
		require.Equal(t, string(cicHash), cicHash2, "cic hash in jwt header should match cic supplied")
	} else {
		payload, err := util.Base64DecodeForJWT(payloadB64)
		require.NoError(t, err)
		require.Contains(t, string(payload), string(cicHash))
	}
}

func TestFindAvaliablePort(t *testing.T) {
	redirects := []string{
		"http://localhost:21111/login-callback",
		"http://localhost:21012/login-callback",
		"http://localhost:30125/login-callback",
	}

	testCases := []struct {
		name           string
		expRedirectURI string
		expError       string
		portsToBlock   int
	}{
		{name: "Happy case", expRedirectURI: "http://localhost:21111/login-callback",
			expError: "", portsToBlock: 0},
		{name: "Happy case: first port in use", expRedirectURI: "http://localhost:21012/login-callback",
			expError: "", portsToBlock: 1},
		{name: "Happy case: first and second port in use", expRedirectURI: "http://localhost:30125/login-callback",
			expError: "", portsToBlock: 2},
		{name: "Check error when all ports in use", expRedirectURI: "",
			expError: "failed to start a listener for the callback", portsToBlock: len(redirects)},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			blockedPorts := []net.Listener{}
			// Simulate the case where a port is in use and the provider has to use a different redirect URI
			for i := 0; i < tc.portsToBlock; i++ {
				parsedUrl, err := url.Parse(redirects[i])
				require.NoError(t, err)
				lnStr := fmt.Sprintf("localhost:%s", parsedUrl.Port())
				ln, err := net.Listen("tcp", lnStr)
				require.NoError(t, err)
				blockedPorts = append(blockedPorts, ln)
			}

			foundURI, ln, err := FindAvaliablePort(redirects)

			if tc.expError != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expError)
				require.Nil(t, ln)
				require.Nil(t, foundURI)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expRedirectURI, foundURI.String())
				require.NotNil(t, ln)
				err = ln.Close()
				require.NoError(t, err)
			}

			for _, lis := range blockedPorts {
				err := lis.Close()
				require.NoError(t, err)
			}
		})
	}
}
