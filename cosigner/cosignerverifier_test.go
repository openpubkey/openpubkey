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

package cosigner_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/openpubkey/openpubkey/cosigner"
	"github.com/openpubkey/openpubkey/discover"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/mocks"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestCosignerVerifier(t *testing.T) {
	// Generate the key pair for our cosigner
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	require.NoError(t, err, "failed to generate key pair")

	cos := &cosigner.Cosigner{
		Alg:    alg,
		Signer: signer,
	}

	pkt, err := mocks.GenerateMockPKToken(t, signer, alg)
	require.NoError(t, err)

	fakeIssuer := "https://example.com"
	kid := "1234"
	cosignerClaims := pktoken.CosignerClaims{
		Issuer:      fakeIssuer,
		KeyID:       kid,
		Algorithm:   cos.Alg.String(),
		AuthID:      "none",
		AuthTime:    time.Now().Unix(),
		IssuedAt:    time.Now().Unix(),
		Expiration:  time.Now().Add(time.Hour).Unix(),
		RedirectURI: "none",
		Nonce:       "test-nonce",
		Typ:         "COS",
	}

	cosToken, err := cos.Cosign(pkt, cosignerClaims)
	require.NoError(t, err, "failed cosign PK Token")
	require.NotNil(t, cosToken, "cosign signature is nil")

	err = pkt.AddSignature(cosToken, pktoken.COS)
	require.NoError(t, err, "failed to add cosign signature to pk token")

	mockPublicKeyFinder := func(ctx context.Context, issuer string) ([]byte, error) {
		keySet := jwk.NewSet()
		jwkKey, err := jwk.PublicKeyOf(signer)
		if err != nil {
			return nil, err
		}
		if err := jwkKey.Set(jwk.AlgorithmKey, alg); err != nil {
			return nil, err
		}
		if err := jwkKey.Set(jwk.KeyIDKey, kid); err != nil {
			return nil, err
		}
		if err := keySet.AddKey(jwkKey); err != nil {
			return nil, err
		}
		return json.MarshalIndent(keySet, "", "  ")
	}

	cosVerifier := cosigner.NewCosignerVerifier(fakeIssuer, cosigner.CosignerVerifierOpts{
		DiscoverPublicKey: &discover.PublicKeyFinder{
			JwksFunc: mockPublicKeyFinder,
		},
	})
	err = cosVerifier.VerifyCosigner(context.Background(), pkt)
	require.NoError(t, err, "failed to verify cosigned pk token")
}
