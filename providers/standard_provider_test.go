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
	"testing"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestStandardProviders(t *testing.T) {
	testCases := []struct {
		name         string
		gqSign       bool
		providerName string
	}{
		{name: "happy case Google",
			providerName: "google",
			gqSign:       false,
		},
		{name: "happy case Google (GQ sign)",
			providerName: "google",
			gqSign:       true,
		},
		{name: "happy case Azure",
			providerName: "azure",
			gqSign:       false,
		},
		{name: "happy case Azure (GQ sign)",
			providerName: "azure",
			gqSign:       true,
		},
		{name: "happy case Hello",
			providerName: "hello",
			gqSign:       false,
		},
		{name: "happy case Hello (GQ sign)",
			providerName: "hello",
			gqSign:       true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var op OpenIdProvider
			var err error

			switch tc.providerName {
			case "google":
				opts := GetDefaultGoogleOpOptions()
				opts.GQSign = tc.gqSign
				op, err = CreateMockGoogleOpWithOpts(opts, "alice@gmail.com")
				require.NoError(t, err, tc.name)
			case "azure":
				opts := GetDefaultAzureOpOptions()
				opts.GQSign = tc.gqSign
				op, err = CreateMockAzureOpWithOpts(opts, "alice@hotmail.com")
				require.NoError(t, err, tc.name)
			case "hello":
				opts := GetDefaultHelloOpOptions()
				opts.GQSign = tc.gqSign
				op, err = CreateMockHelloOpWithOpts(opts, "alice@gmail.com")
				require.NoError(t, err, tc.name)
			default:
				t.Fatalf("unsupported provider name: %s", tc.providerName)
			}

			cic := GenCIC(t)

			tokens, err := op.RequestTokens(context.Background(), cic)
			require.NoError(t, err, tc.name)
			idToken := tokens.IDToken

			cicHash, err := cic.Hash()
			require.NoError(t, err, tc.name)
			require.NotNil(t, cicHash, tc.name)

			headerB64, payloadB64, _, err := jws.SplitCompact(idToken)
			require.NoError(t, err, tc.name)
			headerJson, err := util.Base64DecodeForJWT(headerB64)
			require.NoError(t, err, tc.name)

			if tc.gqSign {
				headers := jws.NewHeaders()
				err = json.Unmarshal(headerJson, &headers)
				require.NoError(t, err, tc.name)
				algFound := headers.Algorithm()
				require.Equal(t, string("GQ256"), algFound.String(), "alg in jwt header should match GQ256")
			} else {
				payload, err := util.Base64DecodeForJWT(payloadB64)
				require.NoError(t, err, tc.name)
				require.Contains(t, string(payload), string(cicHash), tc.name)
			}
			require.Equal(t, "mock-refresh-token", string(tokens.RefreshToken), tc.name)
			require.Equal(t, "mock-access-token", string(tokens.AccessToken), tc.name)

			err = op.VerifyIDToken(context.Background(), idToken, cic)
			require.NoError(t, err, tc.name)

			switch op := op.(type) {
			case RefreshableOpenIdProvider:
				reTokens, err := op.RefreshTokens(context.Background(), tokens.RefreshToken)
				require.NoError(t, err, tc.name)

				require.Equal(t, "mock-refresh-token", string(reTokens.RefreshToken), tc.name)
				require.Equal(t, "mock-access-token", string(reTokens.AccessToken), tc.name)

				err = op.VerifyRefreshedIDToken(context.Background(), tokens.IDToken, reTokens.IDToken)
				require.NoError(t, err, tc.name)

				require.NotEqual(t, tc.providerName, "hello", tc.name, "hello provider is not refreshable")
			default:
				// Make sure a bug doesn't cause us to skip refreshed ID Token tests
				require.NotEqual(t, tc.providerName, "google", tc.name, "google provider should be refreshable")
				require.NotEqual(t, tc.providerName, "azure", tc.name, "azure provider should be refreshable")
			}
		})
	}
}

func TestDefaultConstructors(t *testing.T) {
	googOp := NewGoogleOp()
	require.NotNil(t, googOp, "Google provider should be created")

	azureOp := NewAzureOp()
	require.NotNil(t, azureOp, "Azure provider should be created")

	helloOp := NewHelloOp()
	require.NotNil(t, helloOp, "Hello provider should be created")
}
