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

package choosers

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/openpubkey/openpubkey/providers"
	"github.com/stretchr/testify/require"
)

func TestGoogleSelection(t *testing.T) {

	googleOpOptions := providers.GetDefaultGoogleOpOptions()
	googleOp := providers.NewGoogleOpWithOptions(googleOpOptions)

	azureOpOptions := providers.GetDefaultAzureOpOptions()
	azureOp := providers.NewAzureOpWithOptions(azureOpOptions)

	webChooser := WebChooser{
		OpList:      []providers.BrowserOpenIdProvider{googleOp, azureOp},
		OpenBrowser: false,
	}
	go func() {
		op, err := webChooser.ChooseOp(context.Background())
		require.NoError(t, err)
		require.NotNil(t, op)
		require.Contains(t, op.Issuer(), "accounts.google.com")
	}()

	// Wait until the server is listening
	require.Eventually(t, func() bool {
		return webChooser.server != nil && webChooser.server.Addr != ""
	}, 10*time.Second, 100*time.Millisecond)

	// Make a request to the server to trigger Google selection and get redirect
	resp, err := http.Get("http://" + webChooser.server.Addr + "/select?op=google")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Check the response for the expected redirect
	location, err := resp.Location()
	require.NoError(t, err)
	require.Contains(t, location.String(), "accounts.google.com")
	resp.Body.Close()

}
