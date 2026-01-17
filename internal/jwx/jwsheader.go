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

package jwx

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jws"
)

func HeadersAsMap(headers jws.Headers) (map[string]any, error) {
	headersMap := make(map[string]any)
	for _, key := range headers.Keys() {
		var value any
		if err := headers.Get(key, &value); err != nil {
			return nil, fmt.Errorf("get value for %s: %w", key, err)
		}
		headersMap[key] = value
	}

	return headersMap, nil
}
