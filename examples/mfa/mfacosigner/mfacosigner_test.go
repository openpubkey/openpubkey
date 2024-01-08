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

package mfacosigner

import (
	"fmt"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
	wauthnmock "github.com/openpubkey/openpubkey/examples/mfa/mfacosigner/mocks"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/mocks"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestFullFlow(t *testing.T) {
	// Step 0: Setup
	// Create our PK Token and signer
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	require.NoError(t, err)

	email := "arthur.aardvark@example.com"
	pkt, err := mocks.GenerateMockPKTokenWithEmail(signer, alg, email)
	require.NoError(t, err)

	// Create our MFA Cosigner
	cosSigner, err := util.GenKeyPair(alg)
	require.NoError(t, err)

	kid := "test-kid"
	cosignerURI := "https://example.com"
	rpID := "http://localhost"
	RPOrigin := "http://localhost"

	// WebAuthn configuration
	cfg := &webauthn.Config{
		RPDisplayName: "OpenPubkey",
		RPID:          rpID,
		RPOrigin:      RPOrigin,
	}
	cos, err := New(cosSigner, alg, cosignerURI, kid, cfg)
	require.NoError(t, err)

	// Create our MFA device
	wauthnDevice, err := wauthnmock.NewWebauthnDevice(rpID)
	require.NoError(t, err)

	// Init MFA Cosigner flow
	cosP := client.CosignerProvider{
		Issuer:       "https://example.com",
		CallbackPath: "/mfaredirect",
	}
	redirectURI := fmt.Sprintf("%s%s", "http://localhost:5555", cosP.CallbackPath)

	initAuthMsgJson, _, err := cosP.CreateInitAuthSig(redirectURI)
	sig, err := pkt.NewSignedMessage(initAuthMsgJson, signer)
	authID, err := cos.InitAuth(pkt, sig)
	require.NoError(t, err)

	// Register MFA device
	createCreation, err := cos.BeginRegistration(authID)
	require.NoError(t, err)
	require.NotNil(t, createCreation, "expected cred creation to not be nil")

	credCreationResp, err := wauthnDevice.RegResp(createCreation)
	require.NoError(t, err)

	err = cos.FinishRegistration(authID, credCreationResp)
	require.NoError(t, err)

	// Login MFA device
	credAssert, err := cos.BeginLogin(authID)
	require.NoError(t, err)

	loginResp, err := wauthnDevice.LoginResp(credAssert)
	require.NoError(t, err)

	authcode, ruriRet, err := cos.FinishLogin(authID, loginResp)
	require.NoError(t, err)
	require.NotNil(t, credAssert, "expected cred creation to not be nil")
	require.Equal(t, redirectURI, ruriRet)

	// Sign the authcode
	// and exchange it with the Cosigner to get the PK Token cosigned
	authcodeSig, err := pkt.NewSignedMessage([]byte(authcode), signer)
	require.NoError(t, err)

	cosSig, err := cos.RedeemAuthcode(authcodeSig)
	require.NoError(t, err)
	require.NotNil(t, cosSig, "expected pktCos to be cosigned")

	pkt.AddSignature(cosSig, pktoken.Cos)
}
