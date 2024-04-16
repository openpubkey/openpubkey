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

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/examples/ssh/sshcert"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/stretchr/testify/require"

	"github.com/openpubkey/openpubkey/util"
	"golang.org/x/crypto/ssh"
)

func AllowAllPolicyEnforcer(userDesired string, pkt *pktoken.PKToken) error {
	return nil
}

func TestSshCli(t *testing.T) {
	providerOpts := providers.DefaultMockProviderOpts()
	op, _, _, err := providers.NewMockProvider(providerOpts)
	require.NoError(t, err)

	certBytes, seckeySshPem, err := Login(op)
	require.NoError(t, err)
	require.NotNil(t, certBytes)
	require.NotNil(t, seckeySshPem)
}

func TestAuthorizedKeysCommand(t *testing.T) {
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	require.NoError(t, err)

	providerOpts := providers.DefaultMockProviderOpts()
	op, _, idtTemplate, err := providers.NewMockProvider(providerOpts)
	require.NoError(t, err)

	mockEmail := "arthur.aardvark@example.com"
	idtTemplate.ExtraClaims = map[string]any{
		"email": mockEmail,
	}

	client, err := client.New(op, client.WithSigner(signer, alg))
	require.NoError(t, err)

	pkt, err := client.Auth(context.Background())
	require.NoError(t, err)

	principals := []string{"guest", "dev"}
	cert, err := sshcert.New(pkt, principals)
	require.NoError(t, err)

	sshSigner, err := ssh.NewSignerFromSigner(signer)
	require.NoError(t, err)

	signerMas, err := ssh.NewSignerWithAlgorithms(sshSigner.(ssh.AlgorithmSigner),
		[]string{ssh.KeyAlgoECDSA256})
	require.NoError(t, err)

	sshCert, err := cert.SignCert(signerMas)
	require.NoError(t, err)

	certTypeAndCertB64 := ssh.MarshalAuthorizedKey(sshCert)
	typeArg := strings.Split(string(certTypeAndCertB64), " ")[0]
	certB64Arg := strings.Split(string(certTypeAndCertB64), " ")[1]

	userArg := "user"
	pubkeyList, err := authorizedKeysCommand(userArg, typeArg, certB64Arg, AllowAllPolicyEnforcer, op)
	require.NoError(t, err)

	expectedPubkeyList := "cert-authority ecdsa-sha2-nistp256"
	require.Contains(t, pubkeyList, expectedPubkeyList)

}
