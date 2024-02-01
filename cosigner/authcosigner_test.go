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

package cosigner_test

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/cosigner"
	cosmock "github.com/openpubkey/openpubkey/cosigner/mocks"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/mocks"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestInitAuth(t *testing.T) {
	cos := CreateAuthCosigner(t)

	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	require.NoError(t, err, "failed to generate key pair")

	pkt, err := mocks.GenerateMockPKToken(signer, alg)
	require.NoError(t, err, "failed to generate mock PK Token")

	cosP := client.CosignerProvider{
		Issuer:       "https://example.com",
		CallbackPath: "/mfaredirect",
	}
	redirectURI := fmt.Sprintf("%s/%s", "http://localhost:5555", cosP.CallbackPath)

	initAuthMsgJson, _, err := cosP.CreateInitAuthSig(redirectURI)
	sig, err := pkt.NewSignedMessage(initAuthMsgJson, signer)
	authID1, err := cos.InitAuth(pkt, sig)
	require.NoError(t, err, "failed to initiate auth")
	require.NotEmpty(t, authID1)

	emptySig := []byte{}
	authID2, err := cos.InitAuth(pkt, emptySig)
	require.ErrorContains(t, err, "failed to verify sig: invalid byte sequence")
	require.Empty(t, authID2)
}

func TestRedeemAuthcode(t *testing.T) {
	cos := CreateAuthCosigner(t)

	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	require.NoError(t, err, "failed to generate key pair")

	pkt, err := mocks.GenerateMockPKToken(signer, alg)
	require.NoError(t, err, "failed to generate mock PK Token")

	cosP := client.CosignerProvider{
		Issuer:       "https://example.com",
		CallbackPath: "/mfaredirect",
	}
	redirectURI := fmt.Sprintf("%s/%s", "http://localhost:5555", cosP.CallbackPath)

	diffSigner, err := util.GenKeyPair(alg)
	require.NoError(t, err, "failed to generate key pair")

	diffPkt, err := mocks.GenerateMockPKToken(diffSigner, alg)
	require.NoError(t, err, "failed to generate mock PK Token")

	tests := []struct {
		pkt       *pktoken.PKToken
		signer    crypto.Signer
		wantError bool
	}{
		{pkt: pkt, signer: signer, wantError: false},
		{pkt: pkt, signer: diffSigner, wantError: true},
		{pkt: diffPkt, signer: diffSigner, wantError: false},
		{pkt: diffPkt, signer: signer, wantError: true},
	}

	for i, tc := range tests {
		initAuthMsgJson, _, err := cosP.CreateInitAuthSig(redirectURI)
		sig, err := tc.pkt.NewSignedMessage(initAuthMsgJson, tc.signer)
		authID, err := cos.InitAuth(tc.pkt, sig)
		if !tc.wantError {
			require.NoError(t, err, "test %d: expected: nil, got: %v", i+1, err)
		}
		authcode, err := cos.NewAuthcode(authID)

		acSig, err := tc.pkt.NewSignedMessage([]byte(authcode), tc.signer)
		require.NoError(t, err, "test %d: expected: nil, got: %v", i+1, err)

		cosSig, err := cos.RedeemAuthcode(acSig)
		if tc.wantError {
			require.Error(t, err, "test %d: expected error, got: %v", i+1, err)
		} else {
			require.NoError(t, err, "test %d: expected: nil, got: %v", i+1, err)
			require.NotNil(t, cosSig, "test %d: expected not nil, got: %v", i+1, cosSig)
		}
	}
}

func TestCanOnlyRedeemAuthcodeOnce(t *testing.T) {
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	pkt, err := mocks.GenerateMockPKToken(signer, alg)
	require.NoError(t, err, "failed to generate mock PK Token")

	cos := CreateAuthCosigner(t)

	cosP := client.CosignerProvider{
		Issuer:       "https://example.com",
		CallbackPath: "/mfaredirect",
	}
	redirectURI := fmt.Sprintf("%s/%s", "http://localhost:5555", cosP.CallbackPath)

	// reuse the same authcode twice, it should fail
	initAuthMsgJson, _, err := cosP.CreateInitAuthSig(redirectURI)
	sig, err := pkt.NewSignedMessage(initAuthMsgJson, signer)
	authID, err := cos.InitAuth(pkt, sig)
	require.Empty(t, err)

	authcode, err := cos.NewAuthcode(authID)
	require.Empty(t, err)

	acSig1, err := pkt.NewSignedMessage([]byte(authcode), signer)
	require.Empty(t, err)

	acSig2, err := pkt.NewSignedMessage([]byte(authcode), signer)
	require.Empty(t, err)

	cosSig, err := cos.RedeemAuthcode(acSig1)
	require.NotEmpty(t, cosSig)
	require.Empty(t, err)

	// Should fail because authcode has already been issued
	cosSig, err = cos.RedeemAuthcode(acSig2)
	require.Empty(t, cosSig)
	require.ErrorContains(t, err, "authcode has already been redeemed")
}

func TestNewAuthcodeFailure(t *testing.T) {
	cosAlg := jwa.ES256
	cosSigner, err := util.GenKeyPair(cosAlg)
	require.NoError(t, err, "failed to generate key pair")

	hmacKey := []byte{0x1, 0x2, 0x3}
	store := cosmock.NewAuthStateInMemoryStore(hmacKey)
	cos := cosigner.AuthCosigner{
		Cosigner: cosigner.Cosigner{
			Alg:    cosAlg,
			Signer: cosSigner,
		},
		Issuer:         "https://example.com",
		KeyID:          "kid1234",
		AuthStateStore: store,
	}

	// Ensure failure if AuthID not recorded by cosigner
	authID := "123456789ABCEF123456789ABCEF123456789ABCEF123456789ABCEF"

	authcode, err := cos.NewAuthcode(authID)
	require.ErrorContains(t, err, "no such authID")
	require.Empty(t, authcode)
}

func CreateAuthCosigner(t *testing.T) *cosigner.AuthCosigner {
	cosAlg := jwa.ES256
	signer, err := util.GenKeyPair(cosAlg)
	require.NoError(t, err, "failed to generate key pair")
	issuer := "https://example.com"
	keyID := "kid1234"

	hmacKey := make([]byte, 64)
	_, err = rand.Read(hmacKey)
	require.NoError(t, err, "failed to create auth cosigner")
	store := cosmock.NewAuthStateInMemoryStore(hmacKey)

	authCosigner, err := cosigner.New(signer, cosAlg, issuer, keyID, store)
	require.NoError(t, err, "failed to create auth cosigner")
	return authCosigner
}
