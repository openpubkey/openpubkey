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
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/openpubkey/openpubkey/providers"
	"github.com/sirupsen/logrus"
)

func NewMockWebChooser(opList []providers.BrowserOpenIdProvider, opToChoose string) *WebChooser {
	wc := &WebChooser{
		OpList:        opList,
		OpenBrowser:   false,
		useMockServer: false,
	}
	wc.SetOpenBrowserOverride(BrowserOpenOverride(opToChoose))
	return wc
}

func BrowserOpenOverride(opToChoose string) func(string) error {
	return func(uri string) error {
		// Retry with exponential backoff to wait for server to be ready
		resp, err := retryHTTPGet(uri)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("failed requesting webchooser at %s got status: %d", string(uri), resp.StatusCode)
		}
		selectOpUri := "http://" + resp.Request.URL.Host + "/select?op=" + opToChoose
		// We need to run this in a go func because ChooseOp blocks on getting the redirect URI from the OP
		go func() {
			// Use retry logic here as well to handle timing issues with the OP server
			resp, err := retryHTTPGet(selectOpUri)
			if err != nil {
				// Log error instead of panicking to avoid crashing tests
				logrus.Errorf("Failed to select OP after retries: %v", err)
				return
			}
			defer resp.Body.Close()
		}()
		return nil
	}
}

// retryHTTPGet attempts to GET a URL with exponential backoff for connection refused errors
func retryHTTPGet(url string) (*http.Response, error) {
	maxRetries := 10
	initialDelay := 10 * time.Millisecond
	maxDelay := 500 * time.Millisecond

	var lastErr error
	delay := initialDelay

	for i := 0; i < maxRetries; i++ {
		resp, err := http.Get(url)
		if err == nil {
			return resp, nil
		}

		lastErr = err

		// Only retry on connection refused errors (server not ready yet)
		var netErr *net.OpError
		if errors.As(err, &netErr) && netErr.Op == "dial" {
			// Connection error, likely server not ready - retry with backoff
			if i < maxRetries-1 {
				time.Sleep(delay)
				delay *= 2
				if delay > maxDelay {
					delay = maxDelay
				}
				continue
			}
		}

		// For other errors, fail immediately
		return nil, err
	}

	return nil, fmt.Errorf("failed to connect after %d retries: %w", maxRetries, lastErr)
}
