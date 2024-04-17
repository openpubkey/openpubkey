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

package pktoken

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildCompact(t *testing.T) {
	testCases := []struct {
		name         string
		tokens       [][]byte
		freshIDToken []byte
		expError     string
		expPktCom    []byte
	}{
		{name: "happy case one tokens",
			tokens: [][]byte{
				// base64(one fake protected).base64(fake payload).base64(one fake sig)
				[]byte(`MWZha2Vwcm90ZWN0ZWQ.ZmFrZSBwYXlsb2Fk.b25lIGZha2Ugc2ln`)},
			expPktCom: []byte(`ZmFrZSBwYXlsb2Fk:MWZha2Vwcm90ZWN0ZWQ:b25lIGZha2Ugc2ln`),
		},
		{name: "happy case two tokens",
			tokens: [][]byte{
				// base64(one fake protected).base64(fake payload).base64(one fake sig)
				[]byte(`MWZha2Vwcm90ZWN0ZWQ.ZmFrZSBwYXlsb2Fk.b25lIGZha2Ugc2ln`),
				// base64(two fake protected).base64(fake payload).base64(two fake sig)
				[]byte(`dHdvIGZha2UgcHJvdGVjdGVk.ZmFrZSBwYXlsb2Fk.dHdvIGZha2Ugc2ln`)},
			expPktCom: []byte(`ZmFrZSBwYXlsb2Fk:MWZha2Vwcm90ZWN0ZWQ:b25lIGZha2Ugc2ln:dHdvIGZha2UgcHJvdGVjdGVk:dHdvIGZha2Ugc2ln`),
		},
		{name: "happy case two tokens and refreshed ID Token",
			tokens: [][]byte{
				// base64(one fake protected).base64(fake payload).base64(one fake sig)
				[]byte(`MWZha2Vwcm90ZWN0ZWQ.ZmFrZSBwYXlsb2Fk.b25lIGZha2Ugc2ln`),
				// base64(two fake protected).base64(fake payload).base64(two fake sig)
				[]byte(`dHdvIGZha2UgcHJvdGVjdGVk.ZmFrZSBwYXlsb2Fk.dHdvIGZha2Ugc2ln`)},
			// base64(refreshed protected).base64(refreshed payload).base64(refreshed sig)
			freshIDToken: []byte(`cmVmcmVzaGVkIHByb3RlY3RlZA.cmVmcmVzaGVkIHBheWxvYWQ.cmVmcmVzaGVkIHNpZw`),
			expPktCom:    []byte(`ZmFrZSBwYXlsb2Fk:MWZha2Vwcm90ZWN0ZWQ:b25lIGZha2Ugc2ln:dHdvIGZha2UgcHJvdGVjdGVk:dHdvIGZha2Ugc2ln.cmVmcmVzaGVkIHByb3RlY3RlZA.cmVmcmVzaGVkIHBheWxvYWQ.cmVmcmVzaGVkIHNpZw`),
		},
		{name: "different payloads",
			expError: "payloads in tokens are not the same",
			tokens: [][]byte{
				// base64(one fake protected).base64(fake payload).base64(one fake sig)
				[]byte(`MWZha2Vwcm90ZWN0ZWQ.ZmFrZSBwYXlsb2Fk.b25lIGZha2Ugc2ln`),
				// base64(two fake protected).base64(different payload).base64(two fake sig)
				[]byte(`dHdvIGZha2UgcHJvdGVjdGVk.ZGlmZmVyZW50IHBheWxvYWQ.dHdvIGZha2Ugc2ln`)},
		},
		{name: "malformed Token",
			expError: "invalid number of segments",
			tokens: [][]byte{
				// base64(one fake protected).base64(fake payload).base64(one fake sig)
				[]byte(`MWZha2Vwcm90ZWN0ZWQ.ZmFrZSBwYXlsb2Fk.b25lIGZha2Ugc2ln`),
				// malformed token
				[]byte(`..ZmFrZSBwYXl.sb2Fk.dHdvIGZha2Ugc2ln`)},
		},
		{name: "malformed Refreshed ID Token",
			expError: "invalid refreshed ID Token",
			tokens: [][]byte{
				// base64(one fake protected).base64(fake payload).base64(one fake sig)
				[]byte(`MWZha2Vwcm90ZWN0ZWQ.ZmFrZSBwYXlsb2Fk.b25lIGZha2Ugc2ln`),
				// base64(two fake protected).base64(fake payload).base64(two fake sig)
				[]byte(`dHdvIGZha2UgcHJvdGVjdGVk.ZmFrZSBwYXlsb2Fk.dHdvIGZha2Ugc2ln`)},
			// base64(refreshed protected).base64(refreshed payload).base64(refreshed sig)
			freshIDToken: []byte(`***=BAD!!!###`),
		},
	}
	for _, tc := range testCases {

		t.Run(tc.name, func(t *testing.T) {
			pktCom, err := CompactPKToken(tc.tokens, tc.freshIDToken)
			if tc.expError != "" {
				require.ErrorContains(t, err, tc.expError)
			} else {
				require.NoError(t, err)
				require.Equal(t, string(tc.expPktCom), string(pktCom))
			}
		})
	}
}

func TestFromCompact(t *testing.T) {
	testCases := []struct {
		name            string
		expTokens       [][]byte
		expFreshIDToken []byte
		expError        string
		pktCom          []byte
	}{
		{name: "happy case one tokens",
			expTokens: [][]byte{
				// base64(one fake protected).base64(fake payload).base64(one fake sig)
				[]byte(`MWZha2Vwcm90ZWN0ZWQ.ZmFrZSBwYXlsb2Fk.b25lIGZha2Ugc2ln`)},
			pktCom: []byte(`ZmFrZSBwYXlsb2Fk:MWZha2Vwcm90ZWN0ZWQ:b25lIGZha2Ugc2ln`),
		},
		{name: "happy case two tokens",
			// base64(one fake protected).base64(fake payload).base64(one fake sig)
			expTokens: [][]byte{
				// base64(one fake protected).base64(fake payload).base64(one fake sig)
				[]byte(`MWZha2Vwcm90ZWN0ZWQ.ZmFrZSBwYXlsb2Fk.b25lIGZha2Ugc2ln`),
				// base64(two fake protected).base64(fake payload).base64(two fake sig)
				[]byte(`dHdvIGZha2UgcHJvdGVjdGVk.ZmFrZSBwYXlsb2Fk.dHdvIGZha2Ugc2ln`)},
			pktCom: []byte(`ZmFrZSBwYXlsb2Fk:MWZha2Vwcm90ZWN0ZWQ:b25lIGZha2Ugc2ln:dHdvIGZha2UgcHJvdGVjdGVk:dHdvIGZha2Ugc2ln`),
		},
		{name: "happy case two tokens and refreshed ID Token",
			expTokens: [][]byte{
				// base64(one fake protected).base64(fake payload).base64(one fake sig)
				[]byte(`MWZha2Vwcm90ZWN0ZWQ.ZmFrZSBwYXlsb2Fk.b25lIGZha2Ugc2ln`),
				// base64(two fake protected).base64(fake payload).base64(two fake sig)
				[]byte(`dHdvIGZha2UgcHJvdGVjdGVk.ZmFrZSBwYXlsb2Fk.dHdvIGZha2Ugc2ln`)},
			// base64(refreshed protected).base64(refreshed payload).base64(refreshed sig)
			expFreshIDToken: []byte(`cmVmcmVzaGVkIHByb3RlY3RlZA.cmVmcmVzaGVkIHBheWxvYWQ.cmVmcmVzaGVkIHNpZw`),
			pktCom:          []byte(`ZmFrZSBwYXlsb2Fk:MWZha2Vwcm90ZWN0ZWQ:b25lIGZha2Ugc2ln:dHdvIGZha2UgcHJvdGVjdGVk:dHdvIGZha2Ugc2ln.cmVmcmVzaGVkIHByb3RlY3RlZA.cmVmcmVzaGVkIHBheWxvYWQ.cmVmcmVzaGVkIHNpZw`),
		},
		{name: "malformed Compact PK Token (invalid number of segments)",
			expError: "invalid number of segments",
			pktCom:   []byte(`dHdvIGZha2Ugc2ln:dHdvIGZha2Ugc2ln.cmVmcmVzaGVkIHByb3RlY3RlZA.cmVmcmVzaGVkIHBheWxvYWQ.cmVmcmVzaGVkIHNpZw`),
		},
		{name: "malformed Compact PK Token (invalid refreshed ID Token)",
			expError: "invalid refreshed ID Token",
			pktCom:   []byte(`ZmFrZSBwYXlsb2Fk:MWZha2Vwcm90ZWN0ZWQ:b25lIGZha2Ugc2ln:dHdvIGZha2UgcHJvdGVjdGVk:dHdvIGZha2Ugc2ln.BAD.REFRESHED.ID.TOKEN`),
		},
	}
	for _, tc := range testCases {

		t.Run(tc.name, func(t *testing.T) {
			tokens, freshIDToken, err := SplitCompactPKToken(tc.pktCom)
			if tc.expError != "" {
				require.ErrorContains(t, err, tc.expError)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expTokens, tokens)
				require.Equal(t, tc.expFreshIDToken, freshIDToken)
			}
		})
	}
}
