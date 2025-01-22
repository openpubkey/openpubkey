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

package util

import (
	"encoding/base64"
)

var rawURLEncoding = base64.RawURLEncoding.Strict()

func Base64EncodeForJWT(decoded []byte) []byte {
	return base64Encode(decoded, rawURLEncoding)
}

func Base64DecodeForJWT(encoded []byte) ([]byte, error) {
	return base64Decode(encoded, rawURLEncoding)
}

func base64Encode(decoded []byte, encoding *base64.Encoding) []byte {
	encoded := make([]byte, encoding.EncodedLen(len(decoded)))
	encoding.Encode(encoded, decoded)
	return encoded
}

func base64Decode(encoded []byte, encoding *base64.Encoding) ([]byte, error) {
	decoded := make([]byte, encoding.DecodedLen(len(encoded)))
	n, err := encoding.Decode(decoded, encoded)
	if err != nil {
		return nil, err
	}
	return decoded[:n], nil
}
