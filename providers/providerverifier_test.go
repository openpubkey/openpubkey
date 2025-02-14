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
	"testing"

	"github.com/openpubkey/openpubkey/providers/mocks"
	"github.com/stretchr/testify/require"
)

func TestProviderVerifier(t *testing.T) {
	NONCE_CLAIM := CommitTypesEnum.NONCE_CLAIM
	AUD_CLAIM := CommitTypesEnum.AUD_CLAIM
	GQ_BOUND := CommitTypesEnum.GQ_BOUND
	EMPTY_COMMIT := CommitType{
		Claim:        "",
		GQCommitment: false,
	}

	correctAud := AudPrefixForGQCommitment
	clientID := "test-client-id"
	issuer := "mockIssuer"

	testCases := []struct {
		name        string
		aud         string
		clientID    string
		expError    string
		pvGQSign    bool
		pvGQOnly    bool
		tokenGQSign bool

		tokenCommitType   CommitType
		pvCommitType      CommitType
		SkipClientIDCheck bool
		IssuedAtClaim     int64
		correctCicHash    bool
	}{
		{name: "Claim Commitment happy case", aud: clientID, clientID: clientID,
			tokenCommitType: NONCE_CLAIM, pvCommitType: NONCE_CLAIM,
			expError:       "",
			correctCicHash: true},
		{name: "Claim Commitment (aud) happy case",
			tokenCommitType: AUD_CLAIM, pvCommitType: AUD_CLAIM,
			expError:          "",
			SkipClientIDCheck: true, correctCicHash: true},
		{name: "Claim Commitment wrong audience", aud: "wrong clientID", clientID: clientID,
			tokenCommitType: NONCE_CLAIM, pvCommitType: NONCE_CLAIM,
			expError:       "audience does not contain clientID",
			correctCicHash: true},
		{name: "Claim Commitment no commitment claim", aud: clientID, clientID: clientID,
			tokenCommitType: EMPTY_COMMIT, pvCommitType: EMPTY_COMMIT,
			expError:    "verifier configured with empty commitment claim",
			tokenGQSign: false, correctCicHash: true},
		{name: "Claim Commitment wrong CIC", aud: clientID, clientID: clientID,
			tokenCommitType: NONCE_CLAIM, pvCommitType: NONCE_CLAIM,
			expError:    "commitment claim doesn't match",
			tokenGQSign: false, correctCicHash: false},
		{name: "Claim Commitment GQ happy case", aud: clientID, clientID: clientID,
			tokenCommitType: NONCE_CLAIM, pvCommitType: NONCE_CLAIM,
			expError: "", tokenGQSign: true, correctCicHash: true},
		{name: "Claim Commitment GQ wrong CIC", aud: clientID, clientID: clientID,
			tokenCommitType: NONCE_CLAIM, pvCommitType: NONCE_CLAIM,
			expError: "commitment claim doesn't match", tokenGQSign: true, correctCicHash: false},
		{name: "GQ Commitment happy case", aud: correctAud,
			expError:        "",
			tokenCommitType: GQ_BOUND, pvCommitType: GQ_BOUND,
			tokenGQSign: true, pvGQOnly: true,
			SkipClientIDCheck: true, correctCicHash: true},
		{name: "GQ Commitment wrong aud prefix", aud: "bad value",
			expError:        "audience claim in PK Token's GQCommitment must be prefixed by",
			tokenCommitType: GQ_BOUND, pvCommitType: GQ_BOUND,
			tokenGQSign: true, pvGQOnly: true,
			SkipClientIDCheck: true, correctCicHash: true},
		{name: "GQ Commitment providerVerifier not using GQ Commitment", aud: correctAud,
			expError:        "commitment claim doesn't match",
			tokenCommitType: GQ_BOUND, pvCommitType: NONCE_CLAIM,
			tokenGQSign: true, pvGQOnly: true,
			SkipClientIDCheck: true, correctCicHash: true},
		{name: "GQ Commitment wrong CIC", aud: correctAud,
			expError:        "commitment claim doesn't match",
			tokenCommitType: GQ_BOUND, pvCommitType: GQ_BOUND,
			tokenGQSign: true, pvGQOnly: true,
			SkipClientIDCheck: true, correctCicHash: false},
		{name: "GQ Commitment check client id", aud: correctAud,
			expError:        "GQCommitment requires that audience (aud) is not set to client-id",
			tokenCommitType: GQ_BOUND, pvCommitType: GQ_BOUND,
			tokenGQSign: true, pvGQOnly: true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			idtTemplate := mocks.IDTokenTemplate{
				Issuer:      issuer,
				Nonce:       "empty",
				NoNonce:     false,
				Aud:         "empty",
				Alg:         "RS256",
				NoAlg:       false,
				ExtraClaims: map[string]any{},
			}

			switch tc.tokenCommitType.Claim {
			case "nonce":
				idtTemplate.CommitFunc = mocks.AddNonceCommit
			case "aud":
				idtTemplate.CommitFunc = mocks.AddAudCommit
			default:
				idtTemplate.CommitFunc = mocks.NoClaimCommit
			}

			if tc.aud != "" {
				idtTemplate.Aud = tc.aud
			}

			if tc.IssuedAtClaim != 0 {
				idtTemplate.ExtraClaims["iat"] = tc.IssuedAtClaim
			}
			cic := GenCICExtra(t, map[string]any{})

			// Set gqOnly to gqCommitment since gqCommitment requires gqOnly
			pvGQOnly := tc.tokenCommitType.GQCommitment
			skipClientIDCheck := false //TODO: This should be taken from the testcase

			providerOpts := MockProviderOpts{
				Issuer:     issuer,
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
