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

package jose

type KeyAlgorithm = string

// This list is taken from the built-in values of
// jwx/v3/jwa/signature_gen.go
const (
	ES256  = KeyAlgorithm("ES256")
	ES256K = KeyAlgorithm("ES256K")
	ES384  = KeyAlgorithm("ES384")
	ES512  = KeyAlgorithm("ES512")
	EdDSA  = KeyAlgorithm("EdDSA")
	GQ256  = KeyAlgorithm("GQ256") // We added this algorithm
	HS256  = KeyAlgorithm("HS256")
	HS384  = KeyAlgorithm("HS384")
	HS512  = KeyAlgorithm("HS512")
	None   = KeyAlgorithm("none")
	PS256  = KeyAlgorithm("PS256")
	PS384  = KeyAlgorithm("PS384")
	PS512  = KeyAlgorithm("PS512")
	RS256  = KeyAlgorithm("RS256")
	RS384  = KeyAlgorithm("RS384")
	RS512  = KeyAlgorithm("RS512")
)
