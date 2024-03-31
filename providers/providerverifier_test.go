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

package providers_test

import (
	"context"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/pktoken/mocks"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/providers/backend"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestProviderVerifier(t *testing.T) {
	correctAud := providers.AudPrefixForGQCommitment
	clientID := "test-client-id"

	testCases := []struct {
		name              string
		aud               string
		clientID          string
		commitmentClaim   string
		expError          string
		pvGQSign          bool
		pvGQOnly          bool
		tokenGQSign       bool
		tokenGQCommitment bool
		pvGQCommitment    bool
		SkipClientIDCheck bool
		correctCicHash    bool
		correctCicSig     bool
	}{
		{name: "Claim Commitment happy case", commitmentClaim: "nonce", aud: clientID, clientID: clientID,
			expError:       "",
			correctCicHash: true, correctCicSig: true},
		{name: "Claim Commitment wrong audience", commitmentClaim: "nonce", aud: "wrong clientID", clientID: clientID,
			expError:       "audience does not contain clientID",
			correctCicHash: true, correctCicSig: true},
		{name: "Claim Commitment no commitment claim", commitmentClaim: "", aud: clientID, clientID: clientID,
			expError:    "missing commitment claim",
			tokenGQSign: false, correctCicHash: true, correctCicSig: true},
		{name: "Claim Commitment wrong CIC", commitmentClaim: "nonce", aud: clientID, clientID: clientID,
			expError:    "commitment claim doesn't match",
			tokenGQSign: false, correctCicHash: false, correctCicSig: true},
		{name: "Claim Commitment bad sig on CIC", commitmentClaim: "nonce", aud: clientID, clientID: clientID,
			expError:    "error verifying client signature on PK Token: could not verify message using any of the signatures or keys",
			tokenGQSign: false, correctCicHash: true, correctCicSig: false},
		{name: "Claim Commitment bad sig on wrong CIC", commitmentClaim: "nonce", aud: clientID, clientID: clientID,
			expError: "commitment claim doesn't match", tokenGQSign: false, correctCicHash: false, correctCicSig: false},

		{name: "Claim Commitment GQ happy case", commitmentClaim: "nonce", aud: clientID, clientID: clientID,
			expError: "", tokenGQSign: true, correctCicHash: true, correctCicSig: true},
		{name: "Claim Commitment GQ no commitment claim", commitmentClaim: "", aud: clientID, clientID: clientID,
			expError: "missing commitment claim", tokenGQSign: true, correctCicHash: true, correctCicSig: true},
		{name: "Claim Commitment GQ wrong CIC", commitmentClaim: "nonce", aud: clientID, clientID: clientID,
			expError: "commitment claim doesn't match", tokenGQSign: true, correctCicHash: false, correctCicSig: true},
		{name: "Claim Commitment GQ bad sig on CIC", commitmentClaim: "nonce", aud: clientID, clientID: clientID,
			expError:    "error verifying client signature on PK Token: could not verify message using any of the signatures or keys",
			tokenGQSign: true, correctCicHash: true, correctCicSig: false},
		{name: "Claim Commitment GQ bad sig on wrong CIC", commitmentClaim: "nonce", aud: clientID, clientID: clientID,
			expError: "commitment claim doesn't match", tokenGQSign: true, correctCicHash: false, correctCicSig: false},

		{name: "GQ Commitment happy case", aud: correctAud,
			expError:    "",
			tokenGQSign: true, tokenGQCommitment: true, pvGQOnly: true, pvGQCommitment: true,
			SkipClientIDCheck: true, correctCicHash: true, correctCicSig: true},
		{name: "GQ Commitment wrong aud prefix", aud: "bad value",
			expError:    "audience claim in PK Token's GQCommitment must be prefixed by",
			tokenGQSign: true, tokenGQCommitment: true, pvGQOnly: true, pvGQCommitment: true,
			SkipClientIDCheck: true, correctCicHash: true, correctCicSig: true},
		{name: "GQ Commitment providerVerifier not using GQ Commitment", aud: correctAud,
			expError:    "missing commitment claim",
			tokenGQSign: true, tokenGQCommitment: true, pvGQOnly: true, pvGQCommitment: false,
			SkipClientIDCheck: true, correctCicHash: true, correctCicSig: true},
		{name: "GQ Commitment wrong CIC", aud: correctAud,
			expError:    "commitment claim doesn't match",
			tokenGQSign: true, tokenGQCommitment: true, pvGQOnly: true, pvGQCommitment: true,
			SkipClientIDCheck: true, correctCicHash: false, correctCicSig: true},
		{name: "GQ Commitment bad sig on CIC", aud: correctAud,
			expError:    "error verifying client signature on PK Token: could not verify message using any of the signatures or keys",
			tokenGQSign: true, tokenGQCommitment: true, pvGQOnly: true, pvGQCommitment: true,
			SkipClientIDCheck: true, correctCicHash: true, correctCicSig: false},
		{name: "GQ Commitment bad sig on wrong CIC", aud: correctAud,
			expError:    "commitment claim doesn't match",
			tokenGQSign: true, tokenGQCommitment: true, pvGQOnly: true, pvGQCommitment: true,
			SkipClientIDCheck: true, correctCicHash: false, correctCicSig: false},
		{name: "GQ Commitment check client id", aud: correctAud,
			expError:    "GQCommitment requires that audience (aud) is not set to client-id",
			tokenGQSign: true, tokenGQCommitment: true, pvGQOnly: true, pvGQCommitment: true,
			SkipClientIDCheck: false, correctCicHash: false, correctCicSig: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			alg := jwa.ES256

			signingKey, err := util.GenKeyPair(alg)
			require.NoError(t, err)

			idtTemplate := backend.IDTokenTemplate{
				CommitmentFunc: backend.AddNonceCommit,
				Issuer:         "mockIssuer",
				Nonce:          "empty",
				NoNonce:        false,
				Aud:            "empty",
				Alg:            "RS256",
				NoAlg:          false,
			}

			if tc.commitmentClaim == "nonce" {
				idtTemplate.CommitmentFunc = backend.AddNonceCommit
			} else if tc.commitmentClaim == "aud" {
				idtTemplate.CommitmentFunc = backend.AddAudCommit
			} else {
				idtTemplate.CommitmentFunc = backend.NoClaimCommit
			}

			if tc.aud != "" {
				idtTemplate.Aud = tc.aud
			}

			options := &mocks.MockPKTokenOpts{
				GQSign:         tc.tokenGQSign,
				GQCommitment:   tc.tokenGQCommitment,
				CorrectCicHash: tc.correctCicHash,
				CorrectCicSig:  tc.correctCicSig,
			}

			// TODO: Once provider RequestTokens returns an ID token instead of a PK Token, replace this with a mock provider
			pkt, backendMock, err := mocks.GenerateMockPKTokenWithOpts(t, signingKey, alg, idtTemplate, options)
			require.NoError(t, err)

			issuer, err := pkt.Issuer()
			require.NoError(t, err)
			pv := providers.NewProviderVerifier(issuer, tc.commitmentClaim,
				providers.ProviderVerifierOpts{
					DiscoverPublicKey: &backendMock.PublicKeyFinder,
					GQOnly:            tc.pvGQOnly, GQCommitment: tc.pvGQCommitment,
					ClientID: tc.clientID, SkipClientIDCheck: tc.SkipClientIDCheck})
			err = pv.VerifyProvider(context.Background(), pkt)

			if tc.expError != "" {
				require.ErrorContains(t, err, tc.expError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
