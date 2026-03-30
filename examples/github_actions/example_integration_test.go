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

//go:build integration

package github_actions_example

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGithubActionsIntegration(t *testing.T) {
	// This test runs only in GitHub Actions with id-token: write permission.
	// It exercises the real OIDC flow against GitHub's token endpoint.
	example := &GithubActionsExample{}
	err := example.Run()
	require.NoError(t, err)
}
