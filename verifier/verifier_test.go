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

package verifier_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/discover"
	"github.com/openpubkey/openpubkey/jose"
	pktoken_mocks "github.com/openpubkey/openpubkey/pktoken/mocks"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/providers/mocks"
	"github.com/openpubkey/openpubkey/util"
	"github.com/openpubkey/openpubkey/verifier"
	"github.com/stretchr/testify/require"
)

func NewMockOpenIdProvider(gqSign bool, issuer string, alg string, clientID string, extraClaims map[string]any) (providers.OpenIdProvider, *mocks.MockProviderBackend, error) {
	providerOpts := providers.MockProviderOpts{
		Issuer:     issuer,
		Alg:        alg,
		ClientID:   clientID,
		GQSign:     gqSign,
		NumKeys:    2,
		CommitType: providers.CommitTypesEnum.NONCE_CLAIM,
		VerifierOpts: providers.ProviderVerifierOpts{
			CommitType:        providers.CommitTypesEnum.NONCE_CLAIM,
			SkipClientIDCheck: false,
			GQOnly:            false,
			ClientID:          clientID,
		},
	}

	op, mockBackend, _, err := providers.NewMockProvider(providerOpts)
	if err != nil {
		return nil, nil, err
	}

	expSigningKey, expKeyID, expRecord := mockBackend.RandomSigningKey()

	idTokenTemplate := &mocks.IDTokenTemplate{
		CommitFunc:  mocks.AddNonceCommit,
		Issuer:      op.Issuer(),
		Aud:         clientID,
		KeyID:       expKeyID,
		Alg:         expRecord.Alg,
		ExtraClaims: extraClaims,
		SigningKey:  expSigningKey,
	}
	mockBackend.SetIDTokenTemplate(idTokenTemplate)

	return op, mockBackend, nil
}

func TestVerifier(t *testing.T) {
	issuer := "issuer-provider"
	clientID := "verifier"
	commitType := providers.CommitTypesEnum.NONCE_CLAIM

	noGQSign := false
	GQSign := true
	provider, backend, err := NewMockOpenIdProvider(noGQSign, issuer, "RS256", clientID, map[string]any{
		"aud": clientID,
	})
	require.NoError(t, err)

	providerGQ, backendGQ, err := NewMockOpenIdProvider(GQSign, issuer+"-gq", "RS256", clientID, map[string]any{
		"aud": clientID,
	})
	require.NoError(t, err)

	opkClient, err := client.New(provider)
	require.NoError(t, err)
	pkt, err := opkClient.Auth(context.Background())
	require.NoError(t, err)

	// The below vanilla check is redundant since there is a final verification step as part of the PK token issuance
	pktVerifier, err := verifier.New(provider)
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	require.NoError(t, err)

	// Check if it handles more than one verifier
	pktVerifierTwoProviders, err := verifier.NewFromMany([]verifier.ProviderVerifier{provider, providerGQ})
	require.NoError(t, err)

	opkClient, err = client.New(providerGQ)
	require.NoError(t, err)
	pktGQ, err := opkClient.Auth(context.Background())
	require.NoError(t, err)

	err = pktVerifierTwoProviders.VerifyPKToken(context.Background(), pktGQ)
	require.NoError(t, err)

	// Check if verification fails with incorrect issuer
	wrongIssuer := "https://evil.com/"
	providerVerifier := providers.NewProviderVerifier(wrongIssuer, providers.ProviderVerifierOpts{CommitType: commitType, SkipClientIDCheck: true})
	pktVerifier, err = verifier.New(providerVerifier)
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	require.Error(t, err)

	// Check if verification fails with incorrect commitment claim
	wrongCommitmentClaim := providers.CommitType{Claim: "evil"}
	providerVerifier = providers.NewProviderVerifier(provider.Issuer(), providers.ProviderVerifierOpts{CommitType: wrongCommitmentClaim, SkipClientIDCheck: true})
	pktVerifier, err = verifier.New(providerVerifier)
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	require.Error(t, err)

	// When "aud" claim is a single string, check that Client ID is verified when specified correctly
	providerVerifier = providers.NewProviderVerifier(provider.Issuer(), providers.ProviderVerifierOpts{CommitType: commitType, ClientID: clientID, DiscoverPublicKey: &backend.PublicKeyFinder})
	pktVerifier, err = verifier.New(providerVerifier)
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	require.NoError(t, err)

	// When "aud" claim is a single string, check that an incorrect Client ID when specified, fails
	wrongClientID := "super_evil"
	providerVerifier = providers.NewProviderVerifier(provider.Issuer(), providers.ProviderVerifierOpts{CommitType: commitType, ClientID: wrongClientID, DiscoverPublicKey: &backend.PublicKeyFinder})
	pktVerifier, err = verifier.New(providerVerifier)
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	require.Error(t, err)

	// If audience is a list of strings, make sure verification holds. We use
	// extraClaims because it is resolved just token creation time, allowing
	// us to bypass the clientID being set by the constructor.
	provider, backend, err = NewMockOpenIdProvider(noGQSign, issuer, "RS256", clientID, map[string]any{
		"aud": []string{clientID},
	})
	require.NoError(t, err)

	opkClient, err = client.New(provider)
	require.NoError(t, err)
	pkt, err = opkClient.Auth(context.Background())
	require.NoError(t, err)

	// When "aud" claim is a list of strings, check that Client ID is verified when specified correctly
	providerVerifier = providers.NewProviderVerifier(provider.Issuer(), providers.ProviderVerifierOpts{CommitType: commitType, ClientID: clientID, DiscoverPublicKey: &backend.PublicKeyFinder})
	pktVerifier, err = verifier.New(providerVerifier)
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	require.NoError(t, err)

	// When "aud" claim is a list of strings, check that an incorrect Client ID when specified, fails
	providerVerifier = providers.NewProviderVerifier(provider.Issuer(), providers.ProviderVerifierOpts{CommitType: commitType, ClientID: wrongClientID, DiscoverPublicKey: &backend.PublicKeyFinder})
	pktVerifier, err = verifier.New(providerVerifier)
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	require.Error(t, err)

	// Specify a custom public key discoverer that returns the incorrect key and check that verification fails
	alg := jwa.RS256()
	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pktKeyID, ok := pkt.Op.ProtectedHeaders().KeyID()
	require.True(t, ok)
	jwksFunc, err := discover.MockGetJwksByIssuerOneKey(signer.Public(), pktKeyID, alg.String())
	require.NoError(t, err)

	providerVerifier = providers.NewProviderVerifier(provider.Issuer(), providers.ProviderVerifierOpts{
		CommitType: commitType,
		ClientID:   clientID,
		DiscoverPublicKey: &discover.PublicKeyFinder{
			JwksFunc: jwksFunc,
		},
	})
	pktVerifier, err = verifier.New(providerVerifier)
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	require.Error(t, err)

	// When the PK token does not have a GQ signature but only GQ signatures are allowed, check that verification fails
	providerVerifier = providers.NewProviderVerifier(provider.Issuer(), providers.ProviderVerifierOpts{CommitType: commitType, DiscoverPublicKey: &backend.PublicKeyFinder})
	pktVerifier, err = verifier.New(providerVerifier)
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt, verifier.GQOnly())
	require.Error(t, err)

	// When the PK token has a GQ signature and only GQ signatures are allowed, check that verification succeeds
	opkClient, err = client.New(providerGQ)
	require.NoError(t, err)
	pkt, err = opkClient.Auth(context.Background())
	require.NoError(t, err)

	providerVerifier = providers.NewProviderVerifier(providerGQ.Issuer(), providers.ProviderVerifierOpts{CommitType: commitType, ClientID: clientID, DiscoverPublicKey: &backendGQ.PublicKeyFinder})
	pktVerifier, err = verifier.New(providerVerifier)
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt, verifier.GQOnly())
	require.NoError(t, err)
}

func TestVerifierRefreshedIDToken(t *testing.T) {
	issuer := "issuer-provider"
	clientID := "verifier"
	// commitType := providers.CommitTypesEnum.NONCE_CLAIM

	noGQSign := false
	provider, _, err := NewMockOpenIdProvider(noGQSign, issuer, "RS256", clientID, map[string]any{
		"aud": clientID,
	})
	require.NoError(t, err)

	opkClient, err := client.New(provider)
	require.NoError(t, err)
	pkt, err := opkClient.Auth(context.Background())
	require.NoError(t, err)

	pktVerifier, err := verifier.New(provider, verifier.RequireRefreshedIDToken())
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	require.ErrorContains(t, err, "no refreshed ID Token set")

	rePkt, err := opkClient.Refresh(context.Background())
	require.NoError(t, err)

	err = pktVerifier.VerifyPKToken(context.Background(), rePkt)
	require.NoError(t, err)
}

func TestVerifierExpirationPolicy(t *testing.T) {
	issuer := "issuer-provider"
	clientID := "verifier"

	noGQSign := false
	provider, mockBackend, err := NewMockOpenIdProvider(noGQSign, issuer, "RS256", clientID, map[string]any{
		"aud": clientID,
	})
	require.NoError(t, err)

	// Set the expiration time to 1 second past January 1, 1970
	mockBackend.IDTokenTemplate.ExtraClaims = map[string]any{"exp": 1}

	opkClient, err := client.New(provider)
	require.NoError(t, err)
	pkt, err := opkClient.Auth(context.Background())
	require.NoError(t, err)

	pktVerifier, err := verifier.New(provider,
		verifier.WithExpirationPolicy(verifier.ExpirationPolicies.NEVER_EXPIRE),
	)
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	require.NoError(t, err)

	pktVerifierWithExp, err := verifier.New(provider,
		verifier.WithExpirationPolicy(verifier.ExpirationPolicies.OIDC),
	)
	require.NoError(t, err)
	err = pktVerifierWithExp.VerifyPKToken(context.Background(), pkt)
	require.ErrorContains(t, err, "the ID token has expired (exp = 1)")
}

func TestVerifierRefreshedIDTokenExpirationPolicy(t *testing.T) {
	const (
		noRefresh    = ""
		opRefresh    = "issued by the OP"
		unsigned     = "unsigned"
		otherSubject = "issued by the OP for another subject"
		expired      = "issued by the OP but expired"
	)
	oidcRefreshed := verifier.ExpirationPolicies.OIDC_REFRESHED
	maxAge24h := verifier.ExpirationPolicies.MAX_AGE_24HOURS

	testCases := []struct {
		name             string
		policy           verifier.ExpirationPolicy
		requireRefreshed bool
		idTokenExpired   bool
		refreshedIDToken string
		nonRefreshableOp bool
		expError         string
	}{
		{name: "oidc_refreshed, ID token valid, no refreshed ID token",
			policy: oidcRefreshed, refreshedIDToken: noRefresh},
		{name: "oidc_refreshed, ID token valid, refreshed ID token from OP",
			policy: oidcRefreshed, refreshedIDToken: opRefresh},
		{name: "oidc_refreshed, ID token valid, unsigned refreshed ID token",
			policy: oidcRefreshed, refreshedIDToken: unsigned, expError: "no matching public key"},
		{name: "oidc_refreshed, ID token expired, no refreshed ID token",
			policy: oidcRefreshed, idTokenExpired: true, refreshedIDToken: noRefresh, expError: "ID token is expired and no refresh token found"},
		{name: "oidc_refreshed, ID token expired, refreshed ID token from OP",
			policy: oidcRefreshed, idTokenExpired: true, refreshedIDToken: opRefresh},
		{name: "oidc_refreshed, ID token expired, unsigned refreshed ID token",
			policy: oidcRefreshed, idTokenExpired: true, refreshedIDToken: unsigned, expError: "no matching public key"},
		{name: "oidc_refreshed, ID token expired, refreshed ID token for another subject",
			policy: oidcRefreshed, idTokenExpired: true, refreshedIDToken: otherSubject, expError: "refreshed ID Token is for different subject"},
		{name: "oidc_refreshed, ID token expired, refreshed ID token expired",
			policy: oidcRefreshed, idTokenExpired: true, refreshedIDToken: expired, expError: "the ID token has expired (exp = 2)"},
		{name: "oidc_refreshed, provider cannot verify refreshed ID tokens",
			policy: oidcRefreshed, idTokenExpired: true, refreshedIDToken: unsigned, nonRefreshableOp: true, expError: "does not support it"},
		{name: "24h ignores the refreshed ID token",
			policy: maxAge24h, refreshedIDToken: unsigned},
		{name: "24h with RequireRefreshedIDToken, no refreshed ID token",
			policy: maxAge24h, requireRefreshed: true, refreshedIDToken: noRefresh, expError: "no refreshed ID Token set"},
		{name: "24h with RequireRefreshedIDToken, refreshed ID token from OP",
			policy: maxAge24h, requireRefreshed: true, refreshedIDToken: opRefresh},
		{name: "24h with RequireRefreshedIDToken, unsigned refreshed ID token",
			policy: maxAge24h, requireRefreshed: true, refreshedIDToken: unsigned, expError: "no matching public key"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			clientID := "verifier"
			op, backend, err := NewMockOpenIdProvider(false, "issuer-provider", "RS256", clientID, map[string]any{"aud": clientID})
			require.NoError(t, err)
			if tc.idTokenExpired {
				backend.IDTokenTemplate.ExtraClaims = map[string]any{"exp": 1}
			}
			opkClient, err := client.New(op)
			require.NoError(t, err)
			pkt, err := opkClient.Auth(ctx)
			require.NoError(t, err)

			refreshWithClaims := func(claims map[string]any) {
				backend.IDTokenTemplate.ExtraClaims = claims
				pkt, err = opkClient.Refresh(ctx)
				require.NoError(t, err)
			}
			switch tc.refreshedIDToken {
			case opRefresh:
				refreshWithClaims(nil)
			case otherSubject:
				refreshWithClaims(map[string]any{"sub": "someone-else"})
			case expired:
				refreshWithClaims(map[string]any{"exp": 2})
			case unsigned:
				pkt.FreshIDToken = unsignedIDToken(clientID)
			}

			var pv verifier.ProviderVerifier = op
			if tc.nonRefreshableOp {
				pv = providers.NewNonRefreshableOp(op.(*providers.MockProvider))
			}
			var opts []verifier.VerifierOpts
			if tc.requireRefreshed {
				opts = append(opts, verifier.RequireRefreshedIDToken())
			}

			// Callers can set the policy per provider verifier, as opkssh does,
			// or as the verifier's default.
			perProvider, err := verifier.NewFromMany(
				[]verifier.ProviderVerifier{verifier.ProviderVerifierExpires{ProviderVerifier: pv, Expiration: tc.policy}}, opts...)
			require.NoError(t, err)
			asDefault, err := verifier.New(pv, append(opts, verifier.WithExpirationPolicy(tc.policy))...)
			require.NoError(t, err)

			for name, v := range map[string]*verifier.Verifier{"per-provider policy": perProvider, "default policy": asDefault} {
				err := v.VerifyPKToken(ctx, pkt)
				if tc.expError != "" {
					require.ErrorContains(t, err, tc.expError, name)
				} else {
					require.NoError(t, err, name)
				}
			}
		})
	}
}

// unsignedIDToken returns an ID token for the mock OP's subject with a
// future exp, an alg of none and no valid signature.
func unsignedIDToken(aud string) []byte {
	b64 := base64.RawURLEncoding.EncodeToString
	now := time.Now()
	payload := fmt.Sprintf(`{"iss":"issuer-provider","sub":"me","aud":%q,"iat":%d,"exp":%d}`,
		aud, now.Unix(), now.Add(10*365*24*time.Hour).Unix())
	return []byte(b64([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + b64([]byte(payload)) + "." + b64([]byte("forged")))
}

func TestCICSignature(t *testing.T) {
	clientID := "test_client_id"
	alg := jose.ES256
	cicSigner, err := util.GenKeyPair(alg)
	require.NoError(t, err)
	sigFailure := "error verifying client signature on PK Token"

	testCases := []struct {
		name              string
		expError          string
		commitType        providers.CommitType
		correctCicSig     bool
		skipClientIDCheck bool
	}{
		{name: "happy case", expError: "", commitType: providers.CommitTypesEnum.NONCE_CLAIM,
			correctCicSig: true, skipClientIDCheck: false},
		{name: "bad sig: nonce", expError: sigFailure, commitType: providers.CommitTypesEnum.NONCE_CLAIM,
			correctCicSig: false, skipClientIDCheck: false},
		{name: "bad sig: aud", expError: sigFailure, commitType: providers.CommitTypesEnum.AUD_CLAIM,
			correctCicSig: false, skipClientIDCheck: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			idtTemplate := mocks.DefaultIDTokenTemplate()

			if !tc.skipClientIDCheck {
				idtTemplate.Aud = clientID
			}

			tokenOpts := &pktoken_mocks.MockPKTokenOpts{
				GQSign:         false,
				CommitType:     providers.CommitTypesEnum.NONCE_CLAIM,
				CorrectCicHash: true,
				CorrectCicSig:  tc.correctCicSig,
			}

			switch tc.commitType.Claim {
			case "nonce":
				idtTemplate.CommitFunc = mocks.AddNonceCommit
			case "aud":
				idtTemplate.CommitFunc = mocks.AddAudCommit
			default:
				idtTemplate.CommitFunc = mocks.NoClaimCommit
			}
			pkt, backendMock, err := pktoken_mocks.GenerateMockPKTokenWithOpts(t, cicSigner, alg, idtTemplate, tokenOpts)
			require.NoError(t, err)
			pktVerifier, err := verifier.New(providers.NewProviderVerifier(idtTemplate.Issuer,
				providers.ProviderVerifierOpts{
					ClientID:          clientID,
					CommitType:        tc.commitType,
					SkipClientIDCheck: tc.skipClientIDCheck,
					DiscoverPublicKey: &backendMock.PublicKeyFinder,
				}))
			require.NoError(t, err)
			err = pktVerifier.VerifyPKToken(context.Background(), pkt)
			if tc.expError != "" {
				require.ErrorContains(t, err, tc.expError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGQCommitment(t *testing.T) {
	gqBindingAud := providers.AudPrefixForGQCommitment + "1234"

	testCases := []struct {
		name         string
		aud          string
		expError     string
		gqSign       bool
		gqCommitment bool
		gqOnly       bool
	}{
		{name: "happy case", aud: gqBindingAud, expError: "",
			gqSign: true, gqCommitment: true, gqOnly: true},
		{name: "wrong aud prefix", aud: "bad value", expError: "error verifying PK Token: audience claim in PK Token's GQCommitment must be prefixed by",
			gqSign: true, gqCommitment: true, gqOnly: true},
		{name: "gqSign is false", aud: providers.AudPrefixForGQCommitment, expError: "if GQCommitment is true then GQSign must also be true",
			gqSign: false, gqCommitment: true, gqOnly: true},
		{name: "gqCommitment is false", aud: providers.AudPrefixForGQCommitment, expError: "verifier configured with empty commitment claim",
			gqSign: true, gqCommitment: false, gqOnly: true},
		{name: "gqOnly is false", aud: providers.AudPrefixForGQCommitment, expError: "error verifying PK Token: GQCommitment requires that GQOnly is true, but GQOnly is (false)",
			gqSign: true, gqCommitment: true, gqOnly: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			skipClientIDCheck := true

			commitType := providers.CommitType{
				GQCommitment: tc.gqCommitment,
			}

			clientID := "test_client_id"
			providerOpts := providers.MockProviderOpts{
				Alg:        "RS256",
				ClientID:   clientID,
				GQSign:     tc.gqSign,
				NumKeys:    2,
				CommitType: commitType,
				VerifierOpts: providers.ProviderVerifierOpts{
					CommitType:        commitType,
					SkipClientIDCheck: skipClientIDCheck,
					GQOnly:            tc.gqOnly,
					ClientID:          clientID,
				},
			}

			provider, _, idtTemplate, err := providers.NewMockProvider(providerOpts)
			require.NoError(t, err)

			idtTemplate.Aud = tc.aud

			require.NoError(t, err)

			opkClient, err := client.New(provider)
			require.NoError(t, err)
			pkt, err := opkClient.Auth(context.Background())

			if tc.expError != "" {
				require.ErrorContains(t, err, tc.expError)
			} else {
				require.NoError(t, err)
				var cicHash string
				err := pkt.Op.ProtectedHeaders().Get("cic", &cicHash)
				if tc.gqCommitment == false {
					require.Error(t, err)
					require.Empty(t, cicHash)
				} else {
					require.NoError(t, err)
					require.NotEmpty(t, cicHash)

					cic, err := pkt.GetCicValues()
					require.NoError(t, err)
					require.NotNil(t, cic)
					cicHashFromCIC, err := cic.Hash()
					require.NoError(t, err)
					require.Equal(t, string(cicHashFromCIC), cicHash, "CIC does not match cicHash in GQ commitment")
				}

				require.NoError(t, err)
				pktVerifier, err := verifier.New(provider)
				require.NoError(t, err)
				err = pktVerifier.VerifyPKToken(context.Background(), pkt)
				require.NoError(t, err)
			}
		})
	}
}
