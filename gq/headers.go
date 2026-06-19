// Copyright 2024 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gq

import (
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/openpubkey/openpubkey/util"
)

// pssSaltHeader is the GQ protected-header claim used to carry the PSS salt
// recovered from a PS256-signed JWT, base64url-encoded. It is reserved so that
// callers cannot inject it via WithExtraClaim.
const pssSaltHeader = "pss_salt"

// algFromOrigHeaders returns the alg declared in the original (pre-GQ) JWT's
// protected header. origHeaders is the base64url-encoded header segment of the
// original JWT, as preserved in the GQ token's kid header.
func algFromOrigHeaders(origHeaders []byte) (string, error) {
	headerJSON, err := util.Base64DecodeForJWT(origHeaders)
	if err != nil {
		return "", fmt.Errorf("error decoding original JWT headers: %w", err)
	}
	var parsed struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerJSON, &parsed); err != nil {
		return "", fmt.Errorf("error unmarshalling original JWT headers: %w", err)
	}
	if parsed.Alg == "" {
		return "", fmt.Errorf("missing alg in original JWT headers")
	}
	return parsed.Alg, nil
}

// pssSaltFromGQToken reads and decodes the pss_salt claim from a GQ token's
// protected header. It errors if the claim is missing or malformed.
func pssSaltFromGQToken(gqToken []byte) ([]byte, error) {
	headersB64, _, _, err := jws.SplitCompact(gqToken)
	if err != nil {
		return nil, err
	}
	headerJSON, err := util.Base64DecodeForJWT(headersB64)
	if err != nil {
		return nil, fmt.Errorf("error decoding GQ headers: %w", err)
	}
	var parsed struct {
		PSSSalt string `json:"pss_salt"`
	}
	if err := json.Unmarshal(headerJSON, &parsed); err != nil {
		return nil, fmt.Errorf("error unmarshalling GQ headers: %w", err)
	}
	if parsed.PSSSalt == "" {
		return nil, fmt.Errorf("missing %s claim in GQ headers for PS256 token", pssSaltHeader)
	}
	salt, err := util.Base64DecodeForJWT([]byte(parsed.PSSSalt))
	if err != nil {
		return nil, fmt.Errorf("error decoding %s claim: %w", pssSaltHeader, err)
	}
	// JWA fixes the PS256 salt length to the hash output length (32 bytes). Pin
	// it here so verification is symmetric with signing (which hard-codes
	// pssSaltLength) and rejects spec-violating tokens, rather than relying on
	// the downstream EM mismatch to fail the proof.
	if len(salt) != pssSaltLength {
		return nil, fmt.Errorf("unexpected %s length: got %d, want %d", pssSaltHeader, len(salt), pssSaltLength)
	}
	return salt, nil
}
