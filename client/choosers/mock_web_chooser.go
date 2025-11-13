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
	"fmt"
	"net/http"

	"github.com/openpubkey/openpubkey/providers"
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
		resp, err := http.Get(uri)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("failed requesting webchooser at %s got status: %d", string(uri), resp.StatusCode)
		}
		selectOpUri := "http://" + resp.Request.URL.Host + "/select?op=" + opToChoose

		// We need to run this in a go func because ChooseOp blocks on getting the redirect URI from the OP
		go func() {

			if _, err := http.Get(selectOpUri); err != nil {
				panic(err)
			}
		}()
		return nil
	}
}
