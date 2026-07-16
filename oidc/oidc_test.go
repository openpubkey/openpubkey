// Copyright 2026 OpenPubkey
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

package oidc

import (
	"encoding/json"
	"testing"

	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestAudienceParsing(t *testing.T) {
	testCases := []struct {
		name          string
		payload       string
		errorExpected string
		audExpected   string
	}{
		{
			name:          "Happy case (aud is string)",
			payload:       `{"iss":"https://example.com","aud":"abc"}`,
			errorExpected: "",
			audExpected:   "abc",
		},
		{
			name:          "Happy case (aud is string list)",
			payload:       `{"iss":"https://example.com","aud":["abc","def"]}`,
			errorExpected: "",
			audExpected:   "abc,def",
		},
		{
			name:          "aud empty",
			payload:       `{"iss":"https://example.com","aud":[]}`,
			errorExpected: "",
			audExpected:   "",
		},
		{
			name:          "aud not specified",
			payload:       `{"iss":"https://example.com"}`,
			errorExpected: "",
			audExpected:   "",
		},
		{
			name:          "aud is a number not a string",
			payload:       `{"iss":"https://example.com","aud":123}`,
			errorExpected: "invalid audience type, got float64",
			audExpected:   "",
		},
		{
			name:          "aud list contains a boolean not a string",
			payload:       `{"iss":"https://example.com","aud":["abc", true, "def"]}`,
			errorExpected: "invalid audience type in audience list, got bool",
			audExpected:   "",
		},
		{
			name:          "aud list contains a null not a string",
			payload:       `{"iss":"https://example.com","aud":[null]}`,
			errorExpected: "invalid audience type in audience list, got <nil>",
			audExpected:   "",
		},
		{
			name:          "aud is not a key but an element",
			payload:       `["aud"]`,
			errorExpected: "json: cannot unmarshal array into Go value of type struct",
			audExpected:   "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var claims OidcClaims
			err := json.Unmarshal([]byte(tc.payload), &claims)
			if tc.errorExpected != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errorExpected)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.audExpected, claims.Audience)
			}
		})
	}
}

func TestSplitCompact(t *testing.T) {
	testCases := []struct {
		name          string
		value         string
		expected      []string
		errorExpected string
	}{
		{
			name:          "Happy case",
			value:         `aa.bb.cc`,
			expected:      []string{"aa", "bb", "cc"},
			errorExpected: "",
		},
		{
			name:          "too few segments",
			value:         `aa.bb`,
			expected:      nil,
			errorExpected: "invalid number of segments",
		},
		{
			name:          "too many segments",
			value:         `aa.bb.cc.dd`,
			expected:      nil,
			errorExpected: "invalid number of segments",
		},
		{
			name:          "empty string",
			value:         ``,
			expected:      nil,
			errorExpected: "invalid number of segments",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v1, v2, v3, err := SplitCompact([]byte(tc.value))
			if tc.errorExpected != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errorExpected)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expected, []string{string(v1), string(v2), string(v3)})
			}
		})
	}
}

func TestParseJWTSegment(t *testing.T) {
	testCases := []struct {
		name           string
		jwtSegment     []byte
		claimsExpected OidcClaims
		errorExpected  string
	}{
		{
			name:           "Happy case",
			jwtSegment:     util.Base64EncodeForJWT([]byte(`{"iss":"https://example.com","aud":["xyz"]}`)),
			claimsExpected: OidcClaims{Issuer: "https://example.com", Audience: "xyz"},
			errorExpected:  "",
		},
		{
			name:           "bad base64 encoding",
			jwtSegment:     []byte("invalid-base64"),
			claimsExpected: OidcClaims{},
			errorExpected:  "error decoding segment: illegal base64 data at input byte 12",
		},
		{
			name:           "json unmarshal error",
			jwtSegment:     util.Base64EncodeForJWT([]byte(`["string", "string2"]`)),
			claimsExpected: OidcClaims{},
			errorExpected:  "error parsing segment: json: cannot unmarshal array into Go value of type struct",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var claimsResult OidcClaims
			err := ParseJWTSegment(tc.jwtSegment, &claimsResult)
			if tc.errorExpected != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errorExpected)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.claimsExpected, claimsResult)
			}
		})
	}
}
