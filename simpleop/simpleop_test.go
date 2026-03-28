// Copyright 2026 OpenPubkey
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

package simpleop

import (
	"context"
	"testing"

	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/verifier"
	"github.com/stretchr/testify/require"
)

func TestSimpleOP_NonceClaim(t *testing.T) {
	op, err := New("https://accounts.example.com")
	require.NoError(t, err)

	opkClient, err := client.New(op)
	require.NoError(t, err)

	pkt, err := opkClient.Auth(context.Background())
	require.NoError(t, err)
	require.NotNil(t, pkt)

	v, err := verifier.New(op)
	require.NoError(t, err)

	err = v.VerifyPKToken(context.Background(), pkt)
	require.NoError(t, err)
}

func TestSimpleOP_GQBound(t *testing.T) {
	op, err := New("https://accounts.example.com",
		WithCommitType(providers.CommitTypesEnum.GQ_BOUND),
	)
	require.NoError(t, err)

	opkClient, err := client.New(op)
	require.NoError(t, err)

	pkt, err := opkClient.Auth(context.Background())
	require.NoError(t, err)
	require.NotNil(t, pkt)

	v, err := verifier.New(op)
	require.NoError(t, err)

	err = v.VerifyPKToken(context.Background(), pkt)
	require.NoError(t, err)
}

func TestSimpleOP_AudClaim(t *testing.T) {
	op, err := New("https://accounts.example.com",
		WithCommitType(providers.CommitTypesEnum.AUD_CLAIM),
	)
	require.NoError(t, err)

	opkClient, err := client.New(op)
	require.NoError(t, err)

	pkt, err := opkClient.Auth(context.Background())
	require.NoError(t, err)
	require.NotNil(t, pkt)

	v, err := verifier.New(op)
	require.NoError(t, err)

	err = v.VerifyPKToken(context.Background(), pkt)
	require.NoError(t, err)
}

func TestSimpleOP_DifferentIssuers(t *testing.T) {
	issuers := []string{
		"https://accounts.google.com",
		"https://token.actions.githubusercontent.com",
		"https://gitlab.com",
	}

	for _, issuer := range issuers {
		t.Run(issuer, func(t *testing.T) {
			op, err := New(issuer)
			require.NoError(t, err)
			require.Equal(t, issuer, op.Issuer())

			opkClient, err := client.New(op)
			require.NoError(t, err)

			pkt, err := opkClient.Auth(context.Background())
			require.NoError(t, err)

			v, err := verifier.New(op)
			require.NoError(t, err)

			err = v.VerifyPKToken(context.Background(), pkt)
			require.NoError(t, err)
		})
	}
}

func TestSimpleOP_GQSign(t *testing.T) {
	op, err := New("https://accounts.example.com",
		WithGQSign(true),
	)
	require.NoError(t, err)

	opkClient, err := client.New(op)
	require.NoError(t, err)

	pkt, err := opkClient.Auth(context.Background())
	require.NoError(t, err)
	require.NotNil(t, pkt)
}
