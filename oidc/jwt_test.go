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

package oidc

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJwtMarshaling(t *testing.T) {

	testCases := []struct {
		name        string
		payload     string
		protected   string
		sig         string
		expectedAud string
	}{
		{name: "Happy case",
			// {"iss":"https://example.com","sub":"123","aud":"abc","exp":34,"iat":12,"email":"alice@example.com","nonce":"0x0BEE"}
			payload: "eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiMTIzIiwiYXVkIjoiYWJjIiwiZXhwIjozNCwiaWF0IjoxMiwiZW1haWwiOiJhbGljZUBleGFtcGxlLmNvbSIsIm5vbmNlIjoiMHgwQkVFIn0",
			// {"alg":"RS256","typ":"JWT","kid":"1234"}
			protected:   "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQifQ",
			sig:         "ZmFrZXNpZ25hdHVyZQ", // fakesignature
			expectedAud: "abc",
		},
		{name: "Happy case (aud is list)",
			// {"iss":"https://example.com","sub":"123","aud":["abc","def"],"exp":34,"iat":12,"email":"alice@example.com","nonce":"0x0BEE"}
			payload:     "eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiMTIzIiwiYXVkIjpbImFiYyIsImRlZiJdLCJleHAiOjM0LCJpYXQiOjEyLCJlbWFpbCI6ImFsaWNlQGV4YW1wbGUuY29tIiwibm9uY2UiOiIweDBCRUUifQ",
			protected:   "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQifQ", // {"alg":"RS256","typ":"JWT","kid":"1234"}
			sig:         "ZmFrZXNpZ25hdHVyZQ",                                     // fakesignature
			expectedAud: "abc,def",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jwtCompact := []byte(tc.protected + "." + tc.payload + "." + tc.sig)
			jwt, err := NewJwt(jwtCompact)
			require.NoError(t, err)
			require.NotNil(t, jwt)
			require.Equal(t, tc.expectedAud, jwt.GetClaims().Audience)

			typ, err := jwt.GetSignature().GetTyp()
			require.NoError(t, err)
			require.Equal(t, "JWT", typ)

			pHeader := jwt.GetSignature().GetProtectedClaims()
			require.NotNil(t, pHeader)
			require.Equal(t, "RS256", pHeader.Alg)
		})
	}

}
