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

package providers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	_ "embed"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/providers/mocks"
	"github.com/openpubkey/openpubkey/testutils"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

//go:embed test_dpop_token.json
var expectedDpopToken []byte

var test_jti = "IQS5tYP-bpBPtJsorT4z7g"
var test_iat int64 = 1761937449

func TestCreateDPoPToken(t *testing.T) {
	htm := "POST"
	htu := "https://op.example.com/token"
	authcode := "fake-auth-code"

	// use EdDSA so for so the signatures are deterministic in the test
	alg := "EdDSA"
	signer := testutils.DeterministicTestKeyPair(t, alg)

	jti := test_jti
	iat := test_iat

	dpopToken, err := CreateDpopJwt(htm, htu, jti, authcode, iat, signer, alg)
	require.NoError(t, err)
	require.NotEmpty(t, dpopToken)

	dpopJwt, err := oidc.NewJwt(dpopToken)
	require.NoError(t, err)

	dpopJwtJson, err := dpopJwt.PrettyJson()
	require.NoError(t, err)

	require.Equal(t, string(expectedDpopToken), string(dpopJwtJson))
}

func TestKeyBindingProvider(t *testing.T) {
	// This isn't a great test because it doesn't test the client to OP interaction.
	// It will detect if someone changes ConfigKeyBinding so it returns an error
	issuer := helloIssuer
	providerOverride, err := mocks.NewMockProviderBackend(issuer, "RS256", 2)
	require.NoError(t, err)

	op := &KeyBindingOp{
		StandardOp: StandardOp{
			clientID:                  "also me",
			issuer:                    issuer,
			publicKeyFinder:           providerOverride.PublicKeyFinder,
			requestTokensOverrideFunc: providerOverride.RequestTokensOverrideFunc,
		},
	}

	cic, signer, alg := GenCICDeterministic(t, map[string]any{})
	jwkKey, err := CreateJWK(signer, alg)
	require.NoError(t, err)

	expSigningKey, expKeyID, expRecord := providerOverride.RandomSigningKey()

	idTokenTemplate := mocks.IDTokenTemplate{
		CommitFunc: mocks.AddNonceCommit,
		Issuer:     issuer,
		Nonce:      "empty",
		NoNonce:    false,
		Aud:        "also me",
		KeyID:      expKeyID,
		NoKeyID:    false,
		Alg:        expRecord.Alg,
		NoAlg:      false,
		ExtraClaims: map[string]any{
			"cnf": map[string]any{
				"jwk": jwkKey,
			},
		},
		ExtraProtectedClaims: map[string]any{
			"typ": KEYBOUND_TYP,
		},
		SigningKey: expSigningKey,
	}
	providerOverride.SetIDTokenTemplate(&idTokenTemplate)

	err = op.ConfigKeyBinding(signer, alg)
	require.NoError(t, err)

	tokens, err := op.RequestTokens(context.Background(), cic)
	require.NoError(t, err)

	_, payloadB64, _, err := jws.SplitCompact(tokens.IDToken)
	require.NoError(t, err)

	payload, err := util.Base64DecodeForJWT(payloadB64)
	require.NoError(t, err)

	type payloadCnf struct {
		Jwk json.RawMessage `json:"jwk"`
	}
	payloadClaims := struct {
		Cnf payloadCnf `json:"cnf"`
	}{}
	err = json.Unmarshal(payload, &payloadClaims)
	require.NoError(t, err)

	jwkKeyJson, err := json.Marshal(jwkKey)
	require.NoError(t, err)
	require.Equal(t, string(jwkKeyJson), string(payloadClaims.Cnf.Jwk))

	require.Equal(t, "mock-refresh-token", string(tokens.RefreshToken))
	require.Equal(t, "mock-access-token", string(tokens.AccessToken))

	err = op.VerifyIDToken(context.Background(), tokens.IDToken, cic)
	require.NoError(t, err)
}

type RoundTripperForTester struct {
	Output *http.Request
}

func (t *RoundTripperForTester) RoundTrip(req *http.Request) (*http.Response, error) {
	t.Output = req
	return &http.Response{
		StatusCode: 200,
		Body:       http.NoBody,
	}, nil
}

func TestRoundTripper(t *testing.T) {

	testCases := []struct {
		name        string
		reqForm     url.Values
		refresh     bool
		expectedErr string
	}{
		{name: "Happy case initial token request (authcode)",
			reqForm: url.Values{
				"code":       {"fake-auth-code"},
				"grant_type": {"authorization_code"},
			},
			refresh:     false,
			expectedErr: ""},
		{name: "Happy case refresh token request",
			reqForm: url.Values{
				"grant_type": {"refresh_token"},
			},
			refresh:     true,
			expectedErr: ""},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rtTester := &RoundTripperForTester{}

			alg := "ES256"
			signer, err := util.GenKeyPair(jwa.KeyAlgorithmFrom(alg))
			require.NoError(t, err)

			rt := dPoPRoundTripper{
				Base:   rtTester,
				Signer: signer,
				Alg:    alg,
			}

			bodyStr := tc.reqForm.Encode()
			req, err := http.NewRequest("POST", "https://example.com/oauth/token", strings.NewReader(bodyStr))
			require.NoError(t, err)
			req.Header = make(http.Header)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.ContentLength = int64(len(bodyStr))
			req.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(bodyStr)), nil
			}

			resp, err := rt.RoundTrip(req)

			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Equal(t, 200, resp.StatusCode)

			dpopToken := rtTester.Output.Header.Get("DPoP")

			if !tc.refresh {
				require.Equal(t, "fake-auth-code", rtTester.Output.FormValue("code"))
			}

			require.Equal(t, "POST", rtTester.Output.Method)
			require.NotEmpty(t, dpopToken)

			// Test request that doesn't match a DPoP token request so that it just passes through unchanged
			req, err = http.NewRequest("POST", "https://example.com/other/resource", strings.NewReader(bodyStr))
			require.NoError(t, err)

			resp, err = rt.RoundTrip(req)
			if tc.expectedErr == "" {
				require.NoError(t, err, tc.name)
				require.NotNil(t, resp, tc.name)
				require.Equal(t, 200, resp.StatusCode, tc.name)
				require.Empty(t, rtTester.Output.Header.Get("DPoP"), tc.name)
			} else {
				require.Error(t, err, tc.name)
				require.Contains(t, err.Error(), tc.expectedErr, tc.name)
			}
		})
	}

}
