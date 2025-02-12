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

package providers

// Config declares the minimal interface for an OP (OpenID provider) config. It
// provides methods to get configuration values for a specific OIDC client
// implementation.
type Config interface {
	// ClientID returns the registered client identifier that is valid at the OP
	// issuer
	ClientID() string
	// Issuer returns the OP's issuer URL identifier
	Issuer() string
}
