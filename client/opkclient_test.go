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

package client_test

import (
	"context"
	"crypto/rsa"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestClient(t *testing.T) {
	clientID := "test-client-id"
	commitType := providers.CommitTypesEnum.NONCE_CLAIM

	testCases := []struct {
		name        string
		gq          bool
		signer      bool
		signerAlg   jwa.KeyAlgorithm
		extraClaims map[string]string
	}{
		{name: "without GQ", gq: false, signer: false},
		{name: "with GQ", gq: true, signer: false},
		{name: "with GQ, with signer", gq: true, signer: true, signerAlg: jwa.RS256},
		{name: "with GQ, with signer, with empty extraClaims", gq: true, signer: true, signerAlg: jwa.ES256, extraClaims: map[string]string{}},
		{name: "with GQ, with signer, with extraClaims", gq: true, signer: true, signerAlg: jwa.ES256, extraClaims: map[string]string{"extra": "yes"}},
		{name: "with GQ, with extraClaims", gq: true, signer: false, extraClaims: map[string]string{"extra": "yes", "aaa": "bbb"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			var c *client.OpkClient
			providerOpts := providers.MockProviderOpts{
				Issuer:     "mockIssuer",
				ClientID:   clientID,
				GQSign:     tc.gq,
				NumKeys:    2,
				CommitType: commitType,
				VerifierOpts: providers.ProviderVerifierOpts{
					CommitType:        commitType,
					SkipClientIDCheck: false,
					GQOnly:            false,
					ClientID:          clientID,
				},
			}

			op, _, _, err := providers.NewMockProvider(providerOpts)
			require.NoError(t, err)

			require.NoError(t, err, tc.name)
			if tc.signer {
				signer, err := util.GenKeyPair(tc.signerAlg)
				require.NoError(t, err, tc.name)
				c, err = client.New(op, client.WithSigner(signer, tc.signerAlg))
				require.NoError(t, err, tc.name)
				require.Equal(t, signer, c.GetSigner(), tc.name)
				require.Equal(t, tc.signerAlg, c.GetAlg(), tc.name)
			} else {
				c, err = client.New(op)
				require.NoError(t, err, tc.name)
			}

			var pkt *pktoken.PKToken
			if tc.extraClaims != nil {
				extraClaimsOpts := []client.AuthOpts{}
				for k, v := range tc.extraClaims {
					extraClaimsOpts = append(extraClaimsOpts,
						client.WithExtraClaim(k, v))
				}

				pkt, err = c.Auth(context.Background(), extraClaimsOpts...)
				require.NoError(t, err, tc.name)

				cicPH, err := pkt.Cic.ProtectedHeaders().AsMap(context.TODO())
				require.NoError(t, err, tc.name)

				for k, v := range tc.extraClaims {
					require.Equal(t, v, cicPH[k], tc.name)
				}
			} else {
				pkt, err = c.Auth(context.Background())
				require.NoError(t, err, tc.name)
			}

			providerAlg, ok := pkt.ProviderAlgorithm()
			require.True(t, ok, "missing algorithm", tc.name)

			if tc.gq {
				require.Equal(t, gq.GQ256, providerAlg, tc.name)

				// Verify our GQ signature
				opPubKey, err := op.PublicKeyByToken(context.Background(), pkt.OpToken)
				require.NoError(t, err, tc.name)

				rsaKey, ok := opPubKey.PublicKey.(*rsa.PublicKey)
				require.Equal(t, true, ok)

				ok, err = gq.GQ256VerifyJWT(rsaKey, pkt.OpToken)
				require.NoError(t, err, tc.name)
				require.True(t, ok, "error verifying OP GQ signature on PK Token (ID Token invalid)")
			} else {
				// Expect alg to be RS256 alg when not signing with GQ
				require.Equal(t, jwa.RS256, providerAlg, tc.name)
			}

			cic, err := pkt.GetCicValues()
			require.NoError(t, err)
			err = op.VerifyIDToken(context.Background(), pkt.OpToken, cic)
			require.NoError(t, err, tc.name)

			pktRefreshed, err := c.Refresh(context.Background())
			require.NoError(t, err)
			require.NotNil(t, pktRefreshed)

			// TODO: Add Verification of Refreshed ID Token
		})
	}
}

func TestClientRefreshErrorHandling(t *testing.T) {
	signerAlg := jwa.ES256

	providerOpts := providers.DefaultMockProviderOpts()
	op, _, _, err := providers.NewMockProvider(providerOpts)
	require.NoError(t, err)

	signer, err := util.GenKeyPair(signerAlg)
	require.NoError(t, err)
	c, err := client.New(op, client.WithSigner(signer, jwa.ES256))
	require.NoError(t, err)

	_, err = c.Refresh(context.Background())
	require.ErrorContains(t, err, "no refresh token set")

	// Now that we have called Auth refresh should work
	pkt1, err := c.Auth(context.Background())
	require.NoError(t, err)
	pkt1Com, err := pkt1.Compact()
	require.NoError(t, err)

	pkt2, err := c.Refresh(context.Background())
	require.NoError(t, err)

	pkt2Com, err := pkt2.Compact()
	require.NoError(t, err)
	require.NotEqual(t, string(pkt1Com), string(pkt2Com))

	pkt3, err := c.GetPKToken()
	require.NoError(t, err)
	pkt3com, err := pkt3.Compact()
	require.NoError(t, err)
	require.Equal(t, pkt2Com, pkt3com)

	// Nil out PK Token in client so check we catch the error of a nil PK Token
	c.SetPKToken(nil)
	_, err = c.Refresh(context.Background())
	require.ErrorContains(t, err, "no PK Token set, run Auth() to create a PK Token first")
}

func TestClientRefreshNotSupported(t *testing.T) {
	signerAlg := jwa.ES256

	providerOpts := providers.DefaultMockProviderOpts()
	op, _, _, err := providers.NewMockProvider(providerOpts)
	require.NoError(t, err)

	// Removes RefreshTokens from Op so we can test that client
	// handles Op's that can't refresh tokens
	opRefreshUnsupported := providers.NewNonRefreshableOp(op)

	signer, err := util.GenKeyPair(signerAlg)
	require.NoError(t, err)
	c, err := client.New(opRefreshUnsupported, client.WithSigner(signer, jwa.ES256))
	require.NoError(t, err)

	pkt, err := c.Auth(context.Background())
	require.NoError(t, err)
	require.NotNil(t, pkt)

	_, err = c.Refresh(context.Background())
	require.ErrorContains(t, err, "does not support OIDC refresh requests")
}
