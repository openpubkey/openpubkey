// Copyright 2024 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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
	"strings"
	"testing"

	"github.com/openpubkey/openpubkey/providers/mocks"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestProviderVerifier(t *testing.T) {
	KEY_BOUND := CommitTypesEnum.KEY_BOUND

	keybindingTyp := "id_token+cnf"
	clientID := "test-client-id"
	issuer := "mockIssuer"

	testCases := []struct {
		name        string
		aud         string
		clientID    string
		typClaim    string
		expError    string
		pvGQSign    bool
		pvGQOnly    bool
		tokenGQSign bool
		providerAlg string

		tokenCommitType   CommitType
		pvCommitType      CommitType
		SkipClientIDCheck bool
		IssuedAtClaim     int64
		correctCicHash    bool
	}{
		{name: "Key Binding happy case", aud: clientID, clientID: clientID, typClaim: keybindingTyp,
			tokenCommitType: KEY_BOUND, pvCommitType: KEY_BOUND, providerAlg: "ES256",
			expError:       "",
			correctCicHash: true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			idtTemplate := mocks.IDTokenTemplate{
				Issuer:               issuer,
				Nonce:                "empty",
				NoNonce:              false,
				Aud:                  "empty",
				Alg:                  tc.providerAlg,
				NoAlg:                false,
				ExtraClaims:          map[string]any{},
				ExtraProtectedClaims: map[string]any{},
			}

			cic := GenCICExtra(t, map[string]any{})

			switch tc.tokenCommitType.Claim {
			case "nonce":
				idtTemplate.CommitFunc = mocks.AddNonceCommit
			case "aud":
				idtTemplate.CommitFunc = mocks.AddAudCommit
			case "cnf":
				// For key binding
				cicPublicKey, err := cic.PublicKey()
				require.NoError(t, err)
				idtTemplate.ExtraClaims["cnf"] = map[string]any{
					"jwk": cicPublicKey,
				}
				idtTemplate.CommitFunc = mocks.NoClaimCommit
			default:
				idtTemplate.CommitFunc = mocks.NoClaimCommit
			}

			if tc.aud != "" {
				idtTemplate.Aud = tc.aud
			}

			if tc.IssuedAtClaim != 0 {
				idtTemplate.ExtraClaims["iat"] = tc.IssuedAtClaim
			}

			if tc.typClaim != "" {
				idtTemplate.ExtraProtectedClaims["typ"] = tc.typClaim
			}

			// Set gqOnly to gqCommitment since gqCommitment requires gqOnly
			pvGQOnly := tc.tokenCommitType.GQCommitment
			skipClientIDCheck := false //TODO: This should be taken from the testcase

			providerOpts := MockProviderOpts{
				Issuer:     issuer,
				Alg:        tc.providerAlg,
				ClientID:   clientID,
				GQSign:     tc.tokenGQSign,
				NumKeys:    2,
				CommitType: tc.tokenCommitType,
				VerifierOpts: ProviderVerifierOpts{
					CommitType:        tc.pvCommitType,
					ClientID:          clientID,
					SkipClientIDCheck: skipClientIDCheck,
					GQOnly:            pvGQOnly,
				},
			}

			op, backendMock, _, err := NewMockProvider(providerOpts)
			require.NoError(t, err)
			opSignKey, keyID, _ := backendMock.RandomSigningKey()
			idtTemplate.KeyID = keyID
			idtTemplate.SigningKey = opSignKey

			backendMock.SetIDTokenTemplate(&idtTemplate)

			tokens, err := op.RequestTokens(context.Background(), cic)
			require.NoError(t, err)
			idToken := tokens.IDToken

			if tc.name == "GQ Commitment happy case" {
				fmt.Println("here")
			}
			pv := NewProviderVerifier(issuer,
				ProviderVerifierOpts{
					CommitType:        tc.pvCommitType,
					DiscoverPublicKey: &backendMock.PublicKeyFinder,
					GQOnly:            tc.pvGQOnly,
					ClientID:          tc.clientID,
					SkipClientIDCheck: tc.SkipClientIDCheck,
				})

			// Change the CIC we test against so it doesn't match the commitment
			if !tc.correctCicHash {
				// overwrite the cic with a new cic with a different hash
				cic = GenCICExtra(t, map[string]any{"cause": "differentCicHash"})
			}
			err = pv.VerifyIDToken(context.Background(), idToken, cic)

			if tc.expError != "" {
				require.ErrorContains(t, err, tc.expError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGQCustomAudiencePrefix(t *testing.T) {
	customPrefix := "CUSTOM-PREFIX:"
	clientID := "test-client-id"
	issuer := "mockIssuer"

	testCases := []struct {
		name             string
		aud              string
		gqAudiencePrefix string
		expError         string
	}{
		{
			name:             "Custom prefix happy case",
			aud:              customPrefix,
			gqAudiencePrefix: customPrefix,
			expError:         "",
		},
		{
			name:             "Custom prefix wrong aud",
			aud:              "WRONG-PREFIX:",
			gqAudiencePrefix: customPrefix,
			expError:         "audience claim in PK Token's GQCommitment must be prefixed by",
		},
		{
			name:             "Default prefix when not specified",
			aud:              AudPrefixForGQCommitment,
			gqAudiencePrefix: "", // Will use default
			expError:         "",
		},
		{
			name:             "Default prefix with wrong aud",
			aud:              "wrong-value",
			gqAudiencePrefix: "", // Will use default
			expError:         "audience claim in PK Token's GQCommitment must be prefixed by",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			idtTemplate := mocks.IDTokenTemplate{
				Issuer:      issuer,
				Nonce:       "empty",
				NoNonce:     false,
				Aud:         tc.aud,
				Alg:         "RS256",
				NoAlg:       false,
				ExtraClaims: map[string]any{},
				CommitFunc:  mocks.NoClaimCommit,
			}

			cic := GenCICExtra(t, map[string]any{})

			providerOpts := MockProviderOpts{
				Issuer:     issuer,
				Alg:        "RS256",
				ClientID:   clientID,
				GQSign:     true,
				NumKeys:    2,
				CommitType: CommitTypesEnum.GQ_BOUND,
				VerifierOpts: ProviderVerifierOpts{
					CommitType:        CommitTypesEnum.GQ_BOUND,
					ClientID:          clientID,
					SkipClientIDCheck: true,
					GQOnly:            true,
					GQAudiencePrefix:  tc.gqAudiencePrefix,
				},
			}

			op, backendMock, _, err := NewMockProvider(providerOpts)
			require.NoError(t, err, tc.name)
			opSignKey, keyID, _ := backendMock.RandomSigningKey()
			idtTemplate.KeyID = keyID
			idtTemplate.SigningKey = opSignKey

			backendMock.SetIDTokenTemplate(&idtTemplate)

			tokens, err := op.RequestTokens(context.Background(), cic)
			require.NoError(t, err, tc.name)
			idToken := tokens.IDToken

			pv := NewProviderVerifier(issuer,
				ProviderVerifierOpts{
					CommitType:        CommitTypesEnum.GQ_BOUND,
					DiscoverPublicKey: &backendMock.PublicKeyFinder,
					GQOnly:            true,
					ClientID:          clientID,
					SkipClientIDCheck: true,
					GQAudiencePrefix:  tc.gqAudiencePrefix,
				})

			err = pv.VerifyIDToken(context.Background(), idToken, cic)

			if tc.expError != "" {
				require.ErrorContains(t, err, tc.expError, tc.name)
			} else {
				require.NoError(t, err, tc.name)
			}
		})
	}
}

func TestRejectUnexpectedAlg(t *testing.T) {
	// This test ensures that we correctly handle the case where
	// the protected header has an unexpected alg claim.
	clientID := "test-client-id"
	issuer := "mockIssuer"

	idtTemplate := mocks.IDTokenTemplate{
		Issuer:      issuer,
		Nonce:       "empty",
		NoNonce:     false,
		Aud:         "empty",
		Alg:         "RS256",
		NoAlg:       false,
		ExtraClaims: map[string]any{},
	}

	idtTemplate.CommitFunc = mocks.AddNonceCommit
	idtTemplate.Aud = clientID

	cic := GenCICExtra(t, map[string]any{})

	providerOpts := MockProviderOpts{
		Issuer:     issuer,
		ClientID:   clientID,
		GQSign:     false,
		NumKeys:    2,
		CommitType: CommitTypesEnum.NONCE_CLAIM,
		VerifierOpts: ProviderVerifierOpts{
			CommitType: CommitTypesEnum.NONCE_CLAIM,
			ClientID:   clientID,
		},
	}

	op, backendMock, _, err := NewMockProvider(providerOpts)
	require.NoError(t, err)
	opSignKey, keyID, _ := backendMock.RandomSigningKey()
	idtTemplate.KeyID = keyID
	idtTemplate.SigningKey = opSignKey

	backendMock.SetIDTokenTemplate(&idtTemplate)

	tokens, err := op.RequestTokens(context.Background(), cic)
	require.NoError(t, err)
	idToken := tokens.IDToken

	pv := NewProviderVerifier(issuer,
		ProviderVerifierOpts{
			CommitType:        CommitTypesEnum.NONCE_CLAIM,
			DiscoverPublicKey: &backendMock.PublicKeyFinder,
			GQOnly:            false,
			ClientID:          clientID,
			SkipClientIDCheck: false,
		})

	phBase64 := strings.Split(string(idToken), ".")[0]
	payloadBase64 := strings.Split(string(idToken), ".")[1]
	sigBase64 := strings.Split(string(idToken), ".")[2]

	goodPh := util.Base64EncodeForJWT([]byte(`{"alg":"RS256","kid":"kid-1","typ":"JWT"}`))

	idTokenGood := []byte(fmt.Sprintf("%s.%s.%s", phBase64, payloadBase64, sigBase64))

	err = pv.VerifyIDToken(context.Background(), idTokenGood, cic)
	require.NoError(t, err)

	idTokenBad := []byte(fmt.Sprintf("%s.%s.%s", goodPh, payloadBase64, "bad"))
	err = pv.VerifyIDToken(context.Background(), idTokenBad, cic)
	require.Error(t, err)

	// Use unexpected alg HS256 in the protected header
	wrongAlgPh := util.Base64EncodeForJWT([]byte(`{"alg":"HS256","kid":"kid-1","typ":"JWT"}`))

	idTokenBadAlgPh := []byte(fmt.Sprintf("%s.%s.%s", wrongAlgPh, payloadBase64, "bad"))
	err = pv.VerifyIDToken(context.Background(), idTokenBadAlgPh, cic)
	require.Error(t, err)
}
