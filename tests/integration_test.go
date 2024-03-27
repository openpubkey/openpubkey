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

package integration_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/client/mocks"
	"github.com/openpubkey/openpubkey/client/providers"
	"github.com/stretchr/testify/require"
)

func TestGithub(t *testing.T) {
	var op client.OpenIdProvider
	var err error

	if RunningInGithubActions() {
		op, err = providers.NewGithubOpFromEnvironment()
		require.NoError(t, err)
	} else {
		op, err = mocks.NewMockOpenIdProvider(t, map[string]any{})
		require.NoError(t, err)
	}

	client, err := client.New(op, client.WithSignGQ(true))
	require.NoError(t, err)

	pkt, err := client.Auth(context.TODO())
	require.NoError(t, err)
	require.NotNil(t, pkt)
	fmt.Println("New PK token generated")

	err = op.Verifier().VerifyProvider(context.TODO(), pkt)
	require.NoError(t, err)
}

func RunningInGithubActions() bool {
	_, ok := os.LookupEnv("GITHUB_RUN_ID")
	return ok
}
