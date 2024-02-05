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
	"crypto"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/client/providers"
	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestClient(t *testing.T) {
	testCases := []struct {
		name        string
		gq          bool
		signer      bool
		alg         jwa.KeyAlgorithm
		extraClaims map[string]string
	}{
		{name: "without GQ", gq: false, signer: false},
		{name: "with GQ", gq: true, signer: false},
		{name: "with GQ, with signer", gq: true, signer: true, alg: jwa.RS256},
		{name: "with GQ, with signer, with empty extraClaims ", gq: true, signer: true, alg: jwa.ES256, extraClaims: map[string]string{}},
		{name: "with GQ, with signer, with extraClaims", gq: true, signer: true, alg: jwa.ES256, extraClaims: map[string]string{"extra": "yes"}},
		{name: "with GQ, with extraClaims", gq: true, signer: false, extraClaims: map[string]string{"extra": "yes", "aaa": "bbb"}},
	}

	op, err := providers.NewMockOpenIdProvider()
	require.NoError(t, err, "failed to create mock OpenIdProvider")

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			var c *client.OpkClient
			if tc.signer {
				signer, err := util.GenKeyPair(tc.alg)
				require.NoError(t, err, tc.name)
				c, err = client.New(op, client.WithSignGQ(tc.gq), client.WithSigner(signer, tc.alg))
				require.NoError(t, err, tc.name)
				require.Equal(t, signer, c.GetSigner(), tc.name)
				require.Equal(t, tc.alg, c.GetAlg(), tc.name)
			} else if tc.gq {
				c, err = client.New(op, client.WithSignGQ(tc.gq))
				require.NoError(t, err, tc.name)
			} else {
				c, err = client.New(op)
				require.NoError(t, err, tc.name)
			}
			require.Equal(t, tc.gq, c.GetSignGQ(), tc.name)

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

			jkt, ok := pkt.Op.PublicHeaders().Get("jkt")
			if !ok {
				t.Fatal("missing jkt header")
			}
			data, ok := jkt.([]byte)
			if !ok {
				t.Fatalf("expected jkt header to be a []byte, got %T", jkt)
			}
			jktstr := string(data)

			pubkey, err := op.PublicKey(context.Background(), nil)
			require.NoError(t, err, tc.name)

			pub, err := jwk.FromRaw(pubkey)
			require.NoError(t, err, tc.name)

			thumbprint, err := pub.Thumbprint(crypto.SHA256)
			require.NoError(t, err, tc.name)

			thumbprintStr := string(util.Base64EncodeForJWT(thumbprint))
			require.Equal(t, jktstr, thumbprintStr, "jkt header does not match op thumbprint in "+tc.name)

			alg, ok := pkt.ProviderAlgorithm()
			if !ok {
				t.Fatal(fmt.Errorf("missing algorithm"))
			}

			if tc.gq {
				require.Equal(t, gq.GQ256, alg, tc.name)

				// Verify our GQ signature
				idt, err := pkt.Compact(pkt.Op)
				require.NoError(t, err, tc.name)

				opPubKey, err := op.PublicKey(context.Background(), nil)
				require.NoError(t, err, tc.name)

				sv, err := gq.NewSignerVerifier(opPubKey.(*rsa.PublicKey), client.GQSecurityParameter)
				require.NoError(t, err, tc.name)

				ok := sv.VerifyJWT(idt)
				if !ok {
					t.Fatal(fmt.Errorf("error verifying OP GQ signature on PK Token (ID Token invalid)"))
				}
			} else {
				// Expect alg to be RS256 alg when not signing with GQ
				require.Equal(t, jwa.RS256, alg, tc.name)
			}
		})
	}
}
