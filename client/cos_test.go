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

package client

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCosSimple(t *testing.T) {
	cosP := CosignerProvider{
		Issuer:       "https://example.com",
		CallbackPath: "/mfaredirect",
	}
	redirectURI := fmt.Sprintf("%s/%s", "http://localhost:5555", cosP.CallbackPath)

	initAuthSig, nonce, err := cosP.CreateInitAuthSig(redirectURI)
	require.NotNil(t, initAuthSig)
	require.NotNil(t, nonce)
	require.NoError(t, err)

	pktJson := []byte("fake pkt bytes")
	sig1 := []byte("fake signature one bytes")
	authUri, err := cosP.initAuthURI(pktJson, sig1)
	require.NotNil(t, authUri)
	require.Equal(t, "https://example.com/mfa-auth-init?pkt=ZmFrZSBwa3QgYnl0ZXM&sig1=fake+signature+one+bytes", authUri)
	require.NoError(t, err)

	sig2 := []byte("fake signature two bytes")
	authCodeUri, err := cosP.authcodeURI(sig2)
	require.NotNil(t, authCodeUri)
	require.Equal(t, "https://example.com/sign?sig2=fake+signature+two+bytes", authCodeUri)
	require.NoError(t, err)
}
