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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/openpubkey/openpubkey/discover"
	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/providers/mocks"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestProviderVerifier(t *testing.T) {
	NONCE_CLAIM := CommitTypesEnum.NONCE_CLAIM
	KEY_BOUND := CommitTypesEnum.KEY_BOUND
	AUD_CLAIM := CommitTypesEnum.AUD_CLAIM
	GQ_BOUND := CommitTypesEnum.GQ_BOUND
	EMPTY_COMMIT := CommitType{
		Claim:        "",
		GQCommitment: false,
	}

	keybindingTyp := "dpop+id_token"
	standardTyp := "jwt"

	correctAud := AudPrefixForGQCommitment
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
		{name: "Claim Commitment happy case (RS256)", aud: clientID, clientID: clientID,
			tokenCommitType: NONCE_CLAIM, pvCommitType: NONCE_CLAIM, providerAlg: "RS256",
			expError:       "",
			correctCicHash: true},
		{name: "Claim Commitment happy case (ES256)", aud: clientID, clientID: clientID,
			tokenCommitType: NONCE_CLAIM, pvCommitType: NONCE_CLAIM, providerAlg: "ES256",
			expError:       "",
			correctCicHash: true},
		{name: "Claim Commitment wrong typ claim (ES256)", aud: clientID, clientID: clientID, typClaim: keybindingTyp,
			tokenCommitType: NONCE_CLAIM, pvCommitType: NONCE_CLAIM, providerAlg: "ES256",
			expError:       "expected commitment type nonce but got key-bound ID token (typ=dpop+id_token)",
			correctCicHash: true},
		{name: "Key Binding happy case", aud: clientID, clientID: clientID, typClaim: keybindingTyp,
			tokenCommitType: KEY_BOUND, pvCommitType: KEY_BOUND, providerAlg: "ES256",
			expError:       "",
			correctCicHash: true},
		{name: "Key Binding wrong CIC", aud: clientID, clientID: clientID, typClaim: keybindingTyp,
			tokenCommitType: KEY_BOUND, pvCommitType: KEY_BOUND, providerAlg: "ES256",
			expError:       "jwk thumbprint in cnf claim does not match public key in CIC",
			correctCicHash: false},
		{name: "Key Binding wrong typ claim", aud: clientID, clientID: clientID, typClaim: standardTyp,
			tokenCommitType: KEY_BOUND, pvCommitType: KEY_BOUND, providerAlg: "ES256",
			expError:       "expected key-bound ID token (typ=dpop+id_token) but got ID Token (typ=jwt)",
			correctCicHash: false},
		{name: "Claim Commitment happy case (EdDSA)", aud: clientID, clientID: clientID,
			tokenCommitType: NONCE_CLAIM, pvCommitType: NONCE_CLAIM, providerAlg: "EdDSA",
			expError:       "",
			correctCicHash: true},
		{name: "Claim Commitment happy case (Ed25519)", aud: clientID, clientID: clientID,
			tokenCommitType: NONCE_CLAIM, pvCommitType: NONCE_CLAIM, providerAlg: "Ed25519",
			expError:       "",
			correctCicHash: true},
		{name: "Claim Commitment happy case (PS256)", aud: clientID, clientID: clientID,
			tokenCommitType: NONCE_CLAIM, pvCommitType: NONCE_CLAIM, providerAlg: "PS256",
			expError:       "",
			correctCicHash: true},
		{name: "Claim Commitment wrong CIC (PS256)", aud: clientID, clientID: clientID,
			tokenCommitType: NONCE_CLAIM, pvCommitType: NONCE_CLAIM, providerAlg: "PS256",
			expError:       "commitment claim doesn't match",
			correctCicHash: false},
		{name: "Claim Commitment (aud) happy case (PS256)",
			tokenCommitType: AUD_CLAIM, pvCommitType: AUD_CLAIM, providerAlg: "PS256",
			expError:          "",
			SkipClientIDCheck: true, correctCicHash: true},
		{name: "Claim Commitment (aud) happy case",
			tokenCommitType: AUD_CLAIM, pvCommitType: AUD_CLAIM, providerAlg: "RS256",
			expError:          "",
			SkipClientIDCheck: true, correctCicHash: true},
		{name: "Claim Commitment wrong audience", aud: "wrong clientID", clientID: clientID,
			tokenCommitType: NONCE_CLAIM, pvCommitType: NONCE_CLAIM, providerAlg: "RS256",
			expError:       "audience does not contain clientID",
			correctCicHash: true},
		{name: "Claim Commitment no commitment claim", aud: clientID, clientID: clientID,
			tokenCommitType: EMPTY_COMMIT, pvCommitType: EMPTY_COMMIT, providerAlg: "RS256",
			expError:    "verifier configured with empty commitment claim",
			tokenGQSign: false, correctCicHash: true},
		{name: "Claim Commitment wrong CIC", aud: clientID, clientID: clientID,
			tokenCommitType: NONCE_CLAIM, pvCommitType: NONCE_CLAIM, providerAlg: "RS256",
			expError:    "commitment claim doesn't match",
			tokenGQSign: false, correctCicHash: false},
		{name: "Claim Commitment GQ happy case", aud: clientID, clientID: clientID,
			tokenCommitType: NONCE_CLAIM, pvCommitType: NONCE_CLAIM, providerAlg: "RS256",
			expError: "", tokenGQSign: true, correctCicHash: true},
		{name: "Claim Commitment GQ wrong CIC", aud: clientID, clientID: clientID,
			tokenCommitType: NONCE_CLAIM, pvCommitType: NONCE_CLAIM, providerAlg: "RS256",
			expError: "commitment claim doesn't match", tokenGQSign: true, correctCicHash: false},
		{name: "GQ Commitment happy case", aud: correctAud,
			expError:        "",
			tokenCommitType: GQ_BOUND, pvCommitType: GQ_BOUND, providerAlg: "RS256",
			tokenGQSign: true, pvGQOnly: true,
			SkipClientIDCheck: true, correctCicHash: true},
		{name: "GQ Commitment wrong aud prefix", aud: "bad value",
			expError:        "audience claim in PK Token's GQCommitment must be prefixed by",
			tokenCommitType: GQ_BOUND, pvCommitType: GQ_BOUND, providerAlg: "RS256",
			tokenGQSign: true, pvGQOnly: true,
			SkipClientIDCheck: true, correctCicHash: true},
		{name: "GQ Commitment providerVerifier not using GQ Commitment", aud: correctAud,
			expError:        "commitment claim doesn't match",
			tokenCommitType: GQ_BOUND, pvCommitType: NONCE_CLAIM, providerAlg: "RS256",
			tokenGQSign: true, pvGQOnly: true,
			SkipClientIDCheck: true, correctCicHash: true},
		{name: "GQ Commitment wrong CIC", aud: correctAud,
			expError:        "commitment claim doesn't match",
			tokenCommitType: GQ_BOUND, pvCommitType: GQ_BOUND, providerAlg: "RS256",
			tokenGQSign: true, pvGQOnly: true,
			SkipClientIDCheck: true, correctCicHash: false},
		{name: "GQ Commitment check client id", aud: correctAud,
			expError:        "GQCommitment requires that audience (aud) is not set to client-id",
			tokenCommitType: GQ_BOUND, pvCommitType: GQ_BOUND, providerAlg: "RS256",
			tokenGQSign: true, pvGQOnly: true},
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
				idtTemplate.ExtraClaims["cnf"] = map[string]any{
					"jwk": cic.PublicKey(),
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

func TestGQCommitmentArrayAudReturnsError(t *testing.T) {
	issuer := "https://gitlab.example.com"
	clientID := "test-client"

	idtTemplate := mocks.IDTokenTemplate{
		Issuer:               issuer,
		Nonce:                "empty",
		Aud:                  AudPrefixForGQCommitment,
		Alg:                  "RS256",
		ExtraClaims:          map[string]any{"aud": []any{AudPrefixForGQCommitment + "abc", "other"}},
		ExtraProtectedClaims: map[string]any{},
		CommitFunc:           mocks.NoClaimCommit,
	}
	cic := GenCICExtra(t, map[string]any{})

	op, backendMock, _, err := NewMockProvider(MockProviderOpts{
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
		},
	})
	require.NoError(t, err)
	opSignKey, keyID, _ := backendMock.RandomSigningKey()
	idtTemplate.KeyID = keyID
	idtTemplate.SigningKey = opSignKey
	backendMock.SetIDTokenTemplate(&idtTemplate)

	tokens, err := op.RequestTokens(context.Background(), cic)
	require.NoError(t, err)

	pv := NewProviderVerifier(issuer, ProviderVerifierOpts{
		CommitType:        CommitTypesEnum.GQ_BOUND,
		DiscoverPublicKey: &backendMock.PublicKeyFinder,
		GQOnly:            true,
		SkipClientIDCheck: true,
	})

	// An array aud is valid per RFC 7519; verification must return an error, not panic.
	err = pv.VerifyIDToken(context.Background(), tokens.IDToken, cic)
	require.ErrorContains(t, err, "must be a string")
}

func TestAudClaimPrefix(t *testing.T) {
	const customPrefix = "dd-attest:"
	clientID := "test-client-id"
	issuer := "mockIssuer"

	testCases := []struct {
		name           string
		audClaimPrefix string
		commitFunc     func(*mocks.IDTokenTemplate, string)
		expError       string
	}{
		{
			name:           "prefixed audience verifies",
			audClaimPrefix: customPrefix,
			commitFunc: func(idtTemp *mocks.IDTokenTemplate, cicHash string) {
				idtTemp.Aud = customPrefix + cicHash
			},
		},
		{
			name:           "bare cicHash rejected when a prefix is required",
			audClaimPrefix: customPrefix,
			commitFunc:     mocks.AddAudCommit,
			expError:       "audience claim must be prefixed by",
		},
		{
			name:           "wrong prefix rejected",
			audClaimPrefix: customPrefix,
			commitFunc: func(idtTemp *mocks.IDTokenTemplate, cicHash string) {
				idtTemp.Aud = "other-tool:" + cicHash
			},
			expError: "audience claim must be prefixed by",
		},
		{
			name:           "correct prefix but wrong commitment still rejected",
			audClaimPrefix: customPrefix,
			commitFunc: func(idtTemp *mocks.IDTokenTemplate, _ string) {
				idtTemp.Aud = customPrefix + "not-the-cic-hash"
			},
			expError: "commitment claim doesn't match",
		},
		{
			name:           "unset prefix keeps the bare cicHash behaviour",
			audClaimPrefix: "",
			commitFunc:     mocks.AddAudCommit,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			idtTemplate := mocks.IDTokenTemplate{
				Issuer:      issuer,
				Nonce:       "empty",
				NoNonce:     true,
				Alg:         "RS256",
				ExtraClaims: map[string]any{},
				CommitFunc:  tc.commitFunc,
			}

			cic := GenCICExtra(t, map[string]any{})

			op, backendMock, _, err := NewMockProvider(MockProviderOpts{
				Issuer:     issuer,
				Alg:        "RS256",
				ClientID:   clientID,
				GQSign:     false,
				NumKeys:    2,
				CommitType: CommitTypesEnum.AUD_CLAIM,
				VerifierOpts: ProviderVerifierOpts{
					CommitType:        CommitTypesEnum.AUD_CLAIM,
					ClientID:          clientID,
					SkipClientIDCheck: true,
					AudClaimPrefix:    tc.audClaimPrefix,
				},
			})
			require.NoError(t, err)

			opSignKey, keyID, _ := backendMock.RandomSigningKey()
			idtTemplate.KeyID = keyID
			idtTemplate.SigningKey = opSignKey
			backendMock.SetIDTokenTemplate(&idtTemplate)

			tokens, err := op.RequestTokens(context.Background(), cic)
			require.NoError(t, err)

			pv := NewProviderVerifier(issuer, ProviderVerifierOpts{
				CommitType:        CommitTypesEnum.AUD_CLAIM,
				DiscoverPublicKey: &backendMock.PublicKeyFinder,
				SkipClientIDCheck: true,
				AudClaimPrefix:    tc.audClaimPrefix,
			})

			err = pv.VerifyIDToken(context.Background(), tokens.IDToken, cic)
			if tc.expError != "" {
				require.ErrorContains(t, err, tc.expError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAudClaimPrefixRejectedForOtherCommitTypes(t *testing.T) {
	for _, commitType := range []CommitType{CommitTypesEnum.NONCE_CLAIM, CommitTypesEnum.GQ_BOUND} {
		pv := NewProviderVerifier("mockIssuer", ProviderVerifierOpts{
			CommitType:        commitType,
			SkipClientIDCheck: true,
			GQOnly:            commitType.GQCommitment,
			AudClaimPrefix:    "dd-attest:",
		})

		// The guard runs before the token is parsed.
		err := pv.VerifyIDToken(context.Background(), []byte("not.a.token"), GenCICExtra(t, map[string]any{}))
		require.ErrorContains(t, err, "AudClaimPrefix is set but CommitType is not AUD_CLAIM")
	}
}

func TestAudClaimPrefixArrayAudReturnsError(t *testing.T) {
	const customPrefix = "dd-attest:"
	issuer := "mockIssuer"
	clientID := "test-client-id"

	idtTemplate := mocks.IDTokenTemplate{
		Issuer:      issuer,
		Nonce:       "empty",
		NoNonce:     true,
		Alg:         "RS256",
		ExtraClaims: map[string]any{"aud": []any{customPrefix + "abc", "other"}},
		CommitFunc:  mocks.AddAudCommit,
	}
	cic := GenCICExtra(t, map[string]any{})

	op, backendMock, _, err := NewMockProvider(MockProviderOpts{
		Issuer:     issuer,
		Alg:        "RS256",
		ClientID:   clientID,
		GQSign:     false,
		NumKeys:    2,
		CommitType: CommitTypesEnum.AUD_CLAIM,
		VerifierOpts: ProviderVerifierOpts{
			CommitType:        CommitTypesEnum.AUD_CLAIM,
			ClientID:          clientID,
			SkipClientIDCheck: true,
		},
	})
	require.NoError(t, err)

	opSignKey, keyID, _ := backendMock.RandomSigningKey()
	idtTemplate.KeyID = keyID
	idtTemplate.SigningKey = opSignKey
	backendMock.SetIDTokenTemplate(&idtTemplate)

	tokens, err := op.RequestTokens(context.Background(), cic)
	require.NoError(t, err)

	pv := NewProviderVerifier(issuer, ProviderVerifierOpts{
		CommitType:        CommitTypesEnum.AUD_CLAIM,
		DiscoverPublicKey: &backendMock.PublicKeyFinder,
		SkipClientIDCheck: true,
		AudClaimPrefix:    customPrefix,
	})

	// An array aud is valid per RFC 7519; verification must return an error, not panic.
	err = pv.VerifyIDToken(context.Background(), tokens.IDToken, cic)
	require.ErrorContains(t, err, "must be a string")
}

// undecodableJwksEntries are JWKS entries jwx cannot decode: an EC point not
// on P-256, an unknown key type, and an unknown alg on a known key type. The
// last two reuse the mock OP's kids, so they precede its real keys.
var undecodableJwksEntries = []string{
	`{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iD6aTuMHLsPj6tQXJRx4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7xqOsmKAjSr0tHtjWWE","alg":"ES256","kid":"broken-ec"}`,
	`{"kty":"AKP","alg":"ML-DSA-44","pub":"AAAA","kid":"kid-0"}`,
	`{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlnw-vv-DE0Ts","alg":"Ed99999","kid":"kid-1"}`,
}

func withJwksEntries(t *testing.T, fetch discover.JwksFetchFunc, entries []string) discover.JwksFetchFunc {
	return func(ctx context.Context, issuer string) ([]byte, error) {
		jwksJson, err := fetch(ctx, issuer)
		require.NoError(t, err)
		var jwks struct {
			Keys []json.RawMessage `json:"keys"`
		}
		require.NoError(t, json.Unmarshal(jwksJson, &jwks))
		for _, entry := range entries {
			jwks.Keys = append([]json.RawMessage{json.RawMessage(entry)}, jwks.Keys...)
		}
		return json.Marshal(jwks)
	}
}

func TestProviderVerifierWithUndecodableJwksEntries(t *testing.T) {
	issuer := "mockIssuer"
	clientID := "test-client-id"

	for _, alg := range []string{"RS256", "ES256", "EdDSA", "Ed25519"} {
		t.Run(alg, func(t *testing.T) {
			providerOpts := MockProviderOpts{
				Issuer:     issuer,
				Alg:        alg,
				ClientID:   clientID,
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
			backendMock.SetIDTokenTemplate(&mocks.IDTokenTemplate{
				Issuer:               issuer,
				Nonce:                "empty",
				Aud:                  clientID,
				Alg:                  alg,
				KeyID:                keyID,
				SigningKey:           opSignKey,
				ExtraClaims:          map[string]any{},
				ExtraProtectedClaims: map[string]any{},
				CommitFunc:           mocks.AddNonceCommit,
			})

			cic := GenCIC(t)
			tokens, err := op.RequestTokens(context.Background(), cic)
			require.NoError(t, err)

			finder := backendMock.PublicKeyFinder
			finder.JwksFunc = withJwksEntries(t, finder.JwksFunc, undecodableJwksEntries)
			pv := NewProviderVerifier(issuer, ProviderVerifierOpts{
				CommitType:        CommitTypesEnum.NONCE_CLAIM,
				DiscoverPublicKey: &finder,
				ClientID:          clientID,
			})
			require.NoError(t, pv.VerifyIDToken(context.Background(), tokens.IDToken, cic),
				"An OP JWKS with entries jwx cannot decode must still verify tokens signed with its other keys")
		})
	}
}

func TestVerifyIDTokenRequiresKeyPublishedForTokenAlg(t *testing.T) {
	issuer := "https://issuer.example"
	clientID := "test-client-id"
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	testCases := []struct {
		name     string
		signer   crypto.Signer
		keyAlg   string // empty: the JWK has no alg
		tokenAlg string
		expError string
	}{
		{name: "RS256 key, RS256 token", signer: rsaKey, keyAlg: "RS256", tokenAlg: "RS256"},
		{name: "RS256 key, PS256 token", signer: rsaKey, keyAlg: "RS256", tokenAlg: "PS256", expError: "is published for alg PS256"},
		{name: "PS256 key, RS256 token", signer: rsaKey, keyAlg: "PS256", tokenAlg: "RS256", expError: "is published for alg RS256"},
		{name: "key without alg, RS256 token", signer: rsaKey, tokenAlg: "RS256"},
		{name: "key without alg, PS256 token", signer: rsaKey, tokenAlg: "PS256", expError: "is published for alg PS256"},
		{name: "ES256 key, ES256 token", signer: ecKey, keyAlg: "ES256", tokenAlg: "ES256"},
		{name: "EdDSA key, Ed25519 token", signer: edKey, keyAlg: "EdDSA", tokenAlg: "Ed25519"},
		{name: "Ed25519 key, EdDSA token", signer: edKey, keyAlg: "Ed25519", tokenAlg: "EdDSA"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jwksJson := jwksOfKeys(t, jwkEntry{pubKey: tc.signer.Public(), alg: tc.keyAlg, kid: "k"})
			cic := GenCIC(t)
			idToken := signIDToken(t, tc.signer, tc.tokenAlg, "k", nonceIDTokenPayload(t, issuer, clientID, cic))

			pv := nonceCommitmentVerifier(issuer, clientID, &discover.PublicKeyFinder{JwksFunc: discover.NewMockJwksSource(jwksJson).Fetch})
			err := pv.VerifyIDToken(context.Background(), idToken, cic)
			if tc.expError != "" {
				require.ErrorContains(t, err, tc.expError, "A token must use the alg its key is published for (RFC 8725 section 3.1)")
				return
			}
			require.NoError(t, err)
		})
	}
}

type jwkEntry struct {
	pubKey crypto.PublicKey
	alg    string // empty: the JWK has no alg
	kid    string
	use    string // empty: the JWK has no use
}

func jwksOfKeys(t *testing.T, entries ...jwkEntry) []byte {
	jwks := jwk.NewSet()
	for _, e := range entries {
		key, err := jwk.PublicKeyOf(e.pubKey)
		require.NoError(t, err)
		require.NoError(t, key.Set(jwk.KeyIDKey, e.kid))
		if e.alg != "" {
			require.NoError(t, key.Set(jwk.AlgorithmKey, e.alg))
		}
		if e.use != "" {
			require.NoError(t, key.Set(jwk.KeyUsageKey, e.use))
		}
		require.NoError(t, jwks.AddKey(key))
	}
	jwksJson, err := json.Marshal(jwks)
	require.NoError(t, err)
	return jwksJson
}

// nonceIDTokenPayload returns ID token claims that commit to cic in the nonce.
func nonceIDTokenPayload(t *testing.T, issuer string, clientID string, cic *clientinstance.Claims) []byte {
	cicHash, err := cic.Hash()
	require.NoError(t, err)
	payload, err := json.Marshal(map[string]any{
		"iss": issuer, "aud": clientID, "sub": "me", "nonce": string(cicHash),
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	})
	require.NoError(t, err)
	return payload
}

func signIDToken(t *testing.T, signer crypto.Signer, alg string, kid string, payload []byte) []byte {
	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.KeyIDKey, kid))
	sigAlg, ok := jwa.LookupSignatureAlgorithm(alg)
	require.True(t, ok)
	idToken, err := jws.Sign(payload, jws.WithKey(sigAlg, signer, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)
	return idToken
}

func nonceCommitmentVerifier(issuer string, clientID string, finder *discover.PublicKeyFinder) *DefaultProviderVerifier {
	return NewProviderVerifier(issuer, ProviderVerifierOpts{
		CommitType:        CommitTypesEnum.NONCE_CLAIM,
		ClientID:          clientID,
		DiscoverPublicKey: finder,
	})
}

func TestVerifyIDTokenRejectsAlgConfusion(t *testing.T) {
	issuer := "https://issuer.example"
	clientID := "test-client-id"
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	rsaJwks := jwksOfKeys(t, jwkEntry{pubKey: rsaKey.Public(), alg: "RS256", kid: "k"})

	cic := GenCIC(t)
	payload := nonceIDTokenPayload(t, issuer, clientID, cic)
	payloadB64 := string(util.Base64EncodeForJWT(payload))
	unsignedToken := func(header string, signature []byte) []byte {
		return []byte(string(util.Base64EncodeForJWT([]byte(header))) + "." + payloadB64 + "." + string(util.Base64EncodeForJWT(signature)))
	}
	// The RFC 8725 section 2.1 attack: an HS256 MAC keyed with a serialization
	// of the OP's RSA public key.
	hs256WithSecret := func(secret []byte) []byte {
		header := string(util.Base64EncodeForJWT([]byte(`{"alg":"HS256","kid":"k"}`)))
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(header + "." + payloadB64))
		return []byte(header + "." + payloadB64 + "." + string(util.Base64EncodeForJWT(mac.Sum(nil))))
	}
	der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	testCases := []struct {
		name     string
		jwks     []byte
		idToken  []byte
		expError string
	}{
		{name: "RS256 signed by the OP key", jwks: rsaJwks, idToken: signIDToken(t, rsaKey, "RS256", "k", payload)},
		{name: "alg none", jwks: rsaJwks, idToken: unsignedToken(`{"alg":"none","kid":"k"}`, nil),
			expError: `no key with kid "k" is published for alg none`},
		{name: "HS256 keyed with the PEM public key", jwks: rsaJwks, idToken: hs256WithSecret(pemKey),
			expError: `no key with kid "k" is published for alg HS256`},
		{name: "HS256 keyed with the DER public key", jwks: rsaJwks, idToken: hs256WithSecret(der),
			expError: `no key with kid "k" is published for alg HS256`},
		{name: "HS256 keyed with the JWKS", jwks: rsaJwks, idToken: hs256WithSecret(rsaJwks),
			expError: `no key with kid "k" is published for alg HS256`},
		{name: "alg unknown to jwx", jwks: rsaJwks, idToken: unsignedToken(`{"alg":"XX999","kid":"k"}`, []byte("sig")),
			expError: "jws.Parse"},
		{name: "ES256 with a P-384 key published as ES256",
			jwks:     jwksOfKeys(t, jwkEntry{pubKey: p384Key.Public(), alg: "ES256", kid: "k"}),
			idToken:  signIDToken(t, p384Key, "ES256", "k", payload),
			expError: "algorithm ES256 requires a P-256 key, got P-384"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pv := nonceCommitmentVerifier(issuer, clientID, &discover.PublicKeyFinder{JwksFunc: discover.NewMockJwksSource(tc.jwks).Fetch})
			err := pv.VerifyIDToken(context.Background(), tc.idToken, cic)
			if tc.expError != "" {
				require.ErrorContains(t, err, tc.expError)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestVerifyIDTokenRefetchesJwksForRotatedKey(t *testing.T) {
	issuer := "https://issuer.example"
	clientID := "test-client-id"
	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	testCases := []struct {
		name     string
		gqSigned bool
	}{
		{name: "RS256"},
		{name: "GQ256", gqSigned: true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			source := discover.NewMockJwksSource(jwksOfKeys(t, jwkEntry{pubKey: oldKey.Public(), alg: "RS256", kid: "old"}))
			finder := discover.NewPubkeyFinderWithCache(source.Fetch, discover.NewMapDiscoveryCache(), time.Hour)
			_, err := finder.ByKeyID(context.Background(), issuer, "old", true)
			require.NoError(t, err)
			source.SetJwks(jwksOfKeys(t,
				jwkEntry{pubKey: oldKey.Public(), alg: "RS256", kid: "old"},
				jwkEntry{pubKey: newKey.Public(), alg: "RS256", kid: "new"},
			))

			cic := GenCIC(t)
			idToken := signIDToken(t, newKey, "RS256", "new", nonceIDTokenPayload(t, issuer, clientID, cic))
			if tc.gqSigned {
				idToken, err = gq.GQ256SignJWT(&newKey.PublicKey, idToken)
				require.NoError(t, err)
			}

			err = nonceCommitmentVerifier(issuer, clientID, finder).VerifyIDToken(context.Background(), idToken, cic)
			require.NoError(t, err, "A kid missing from the cached JWKS must trigger a fresh fetch (OIDC Core 10.1.1)")
			require.Equal(t, 2, source.Calls(), "Expected the cached fetch and one fresh fetch")
		})
	}
}

func TestVerifyIDTokenRejectsEncryptionKey(t *testing.T) {
	issuer := "https://issuer.example"
	clientID := "test-client-id"
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwks := jwksOfKeys(t, jwkEntry{pubKey: rsaKey.Public(), alg: "RS256", kid: "k", use: "enc"})

	cic := GenCIC(t)
	idToken := signIDToken(t, rsaKey, "RS256", "k", nonceIDTokenPayload(t, issuer, clientID, cic))
	pv := nonceCommitmentVerifier(issuer, clientID, &discover.PublicKeyFinder{JwksFunc: discover.NewMockJwksSource(jwks).Fetch})
	err = pv.VerifyIDToken(context.Background(), idToken, cic)
	require.ErrorContains(t, err, `key is published for use "enc", not "sig"`)
}
