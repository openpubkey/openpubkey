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

package cert

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/client/providers"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestCreateX509Cert(t *testing.T) {
	// generate pktoken
	signer, err := util.GenKeyPair(jwa.ES256)
	require.NoError(t, err)
	provider, err := providers.NewMockOpenIdProvider()
	require.NoError(t, err)

	opkClient := client.OpkClient{Op: provider}
	pkToken, err := opkClient.OidcAuth(context.Background(), signer, jwa.ES256, map[string]any{}, true)
	require.NoError(t, err)

	// create x509 cert from pk token
	cert, err := CreateX509Cert(pkToken, signer)
	require.NoError(t, err)

	p, _ := pem.Decode(cert)
	result, err := x509.ParseCertificate(p.Bytes)
	require.NoError(t, err)

	// test cert SubjectKeyId field contains PK token
	pkTokenJSON, err := json.Marshal(pkToken)
	require.NoError(t, err)
	require.Equal(t, string(result.SubjectKeyId), string(pkTokenJSON),
		"certificate subject key id does not match PK token")

	// test cert RawSubjectPublicKeyInfo field contains ephemeral public key
	ecPub, err := x509.MarshalPKIXPublicKey(signer.Public())
	require.NoError(t, err)
	require.Equal(t, string(ecPub), string(result.RawSubjectPublicKeyInfo),
		"certificate raw subject public key info does not match ephemeral public key")

	// test cert common name == pktoken sub claim
	var payload struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(pkToken.Payload, &payload); err != nil {
		require.NoError(t, err)
	}

	require.Equal(t, payload.Subject, result.Subject.CommonName,
		"cert common name does not equal pk token sub claim")

}
