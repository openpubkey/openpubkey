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
	_ "embed"
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

func TestJwtCompare(t *testing.T) {

	testCases := []struct {
		name                           string
		t1, t2                         string
		expIdErr, expAgeErr, expCnfErr string
		checkSameCnf                   bool
	}{
		{name: "Happy case",
			// {"alg":"RS256","typ":"JWT","kid":"1234"}.{"iss":"https://example.com","sub":"123","aud":"abc","exp":34,"iat":12,"email":"alice@example.com","nonce":"0x0BEE"}.fakesignature
			t1: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQifQ.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiMTIzIiwiYXVkIjoiYWJjIiwiZXhwIjozNCwiaWF0IjoxMiwiZW1haWwiOiJhbGljZUBleGFtcGxlLmNvbSIsIm5vbmNlIjoiMHgwQkVFIn0.ZmFrZXNpZ25hdHVyZQ",
			// {"alg":"RS256","typ":"JWT","kid":"1234"}.{"iss":"https://example.com","sub":"123","aud":"abc","exp":35,"iat":12,"email":"alice@example.com"}.fakesignature
			t2: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQifQ.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiMTIzIiwiYXVkIjoiYWJjIiwiZXhwIjozNSwiaWF0IjoxMiwiZW1haWwiOiJhbGljZUBleGFtcGxlLmNvbSJ9.ZmFrZXNpZ25hdHVyZQ",
		},
		{name: "Different Subjects",
			// {"alg":"RS256","typ":"JWT","kid":"1234"}.{"iss":"https://example.com","sub":"123","aud":"abc","exp":34,"iat":12,"email":"alice@example.com","nonce":"0x0BEE"}.fakesignature
			t1: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQifQ.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiMTIzIiwiYXVkIjoiYWJjIiwiZXhwIjozNCwiaWF0IjoxMiwiZW1haWwiOiJhbGljZUBleGFtcGxlLmNvbSIsIm5vbmNlIjoiMHgwQkVFIn0.ZmFrZXNpZ25hdHVyZQ",
			// {"alg":"RS256","typ":"JWT","kid":"1234"}.{"iss":"https://example.com","sub":"567","aud":"abc","exp":35,"iat":12,"email":"alice@example.com"}.fakesignature
			t2:       "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQifQ.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiNTY3IiwiYXVkIjoiYWJjIiwiZXhwIjozNSwiaWF0IjoxMiwiZW1haWwiOiJhbGljZUBleGFtcGxlLmNvbSJ9.ZmFrZXNpZ25hdHVyZQ",
			expIdErr: "tokens have different subject claims",
		},
		{name: "Different Issuers",
			// {"alg":"RS256","typ":"JWT","kid":"1234"}.{"iss":"https://example.com","sub":"123","aud":"abc","exp":34,"iat":12,"email":"alice@example.com","nonce":"0x0BEE"}.fakesignature
			t1: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQifQ.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiMTIzIiwiYXVkIjoiYWJjIiwiZXhwIjozNCwiaWF0IjoxMiwiZW1haWwiOiJhbGljZUBleGFtcGxlLmNvbSIsIm5vbmNlIjoiMHgwQkVFIn0.ZmFrZXNpZ25hdHVyZQ",
			// {"alg":"RS256","typ":"JWT","kid":"1234"}.{"iss":"https://notexample.com","sub":"123","aud":"abc","exp":35,"iat":12,"email":"alice@example.com"}.fakesignature
			t2:       "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQifQ.eyJpc3MiOiJodHRwczovL25vdGV4YW1wbGUuY29tIiwic3ViIjoiMTIzIiwiYXVkIjoiYWJjIiwiZXhwIjozNSwiaWF0IjoxMiwiZW1haWwiOiJhbGljZUBleGFtcGxlLmNvbSJ9.ZmFrZXNpZ25hdHVyZQ",
			expIdErr: "tokens have different issuers",
		},
		{name: "Age mismatch t1 issued after t2",
			// {"alg":"RS256","typ":"JWT","kid":"1234"}.{"iss":"https://example.com","sub":"123","aud":"abc","exp":34,"iat":12,"email":"alice@example.com","nonce":"0x0BEE"}.fakesignature
			t1: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQifQ.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiMTIzIiwiYXVkIjoiYWJjIiwiZXhwIjozNCwiaWF0IjoxMiwiZW1haWwiOiJhbGljZUBleGFtcGxlLmNvbSIsIm5vbmNlIjoiMHgwQkVFIn0.ZmFrZXNpZ25hdHVyZQ",
			// {"alg":"RS256","typ":"JWT","kid":"1234"}.{"iss":"https://example.com","sub":"123","aud":"abc","exp":35,"iat":10,"email":"alice@example.com"}.fakesignature
			t2:        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQifQ.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiMTIzIiwiYXVkIjoiYWJjIiwiZXhwIjozNSwiaWF0IjoxMCwiZW1haWwiOiJhbGljZUBleGFtcGxlLmNvbSJ9.ZmFrZXNpZ25hdHVyZQ",
			expAgeErr: "tokens not issued in correct order",
		},
		{name: "Happy case cnf Matches",
			// {"alg":"RS256","typ":"JWT","kid":"1234"}.{"iss":"https://example.com","sub":"123","aud":"abc","cnf":{"jwk":{"alg":"ES256","crv":"P-256","kty":"EC","x":"6hgrwR47GqR6wpeTUAusxBYbwnO5I_B5nTaO0YH75Uk","y":"H0ZtI1Bbytlvfn3ej3eW0qVkXpyuFSRVmuLtwRq3UyM"}},"exp":34,"iat":12,"email":"alice@example.com","nonce":"0x0BEE"}.fakesignature
			t1: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQifQ.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiMTIzIiwiYXVkIjoiYWJjIiwiY25mIjp7Imp3ayI6eyJhbGciOiJFUzI1NiIsImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiNmhncndSNDdHcVI2d3BlVFVBdXN4Qllid25PNUlfQjVuVGFPMFlINzVVayIsInkiOiJIMFp0STFCYnl0bHZmbjNlajNlVzBxVmtYcHl1RlNSVm11THR3UnEzVXlNIn19LCJleHAiOjM0LCJpYXQiOjEyLCJlbWFpbCI6ImFsaWNlQGV4YW1wbGUuY29tIiwibm9uY2UiOiIweDBCRUUifQ.ZmFrZXNpZ25hdHVyZQ",
			// {"alg":"RS256","typ":"JWT","kid":"1234"}.{"iss":"https://example.com","sub":"123","aud":"abc","cnf":{"jwk":{"alg":"ES256","crv":"P-256","kty":"EC","x":"6hgrwR47GqR6wpeTUAusxBYbwnO5I_B5nTaO0YH75Uk","y":"H0ZtI1Bbytlvfn3ej3eW0qVkXpyuFSRVmuLtwRq3UyM"}},"exp":34,"iat":14,"email":"alice@example.com","nonce":"0x0EEB"}.fakesignature
			t2:           "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQifQ.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiMTIzIiwiYXVkIjoiYWJjIiwiY25mIjp7Imp3ayI6eyJhbGciOiJFUzI1NiIsImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiNmhncndSNDdHcVI2d3BlVFVBdXN4Qllid25PNUlfQjVuVGFPMFlINzVVayIsInkiOiJIMFp0STFCYnl0bHZmbjNlajNlVzBxVmtYcHl1RlNSVm11THR3UnEzVXlNIn19LCJleHAiOjM0LCJpYXQiOjE0LCJlbWFpbCI6ImFsaWNlQGV4YW1wbGUuY29tIiwibm9uY2UiOiIweDBFRUIifQ.ZmFrZXNpZ25hdHVyZQ",
			checkSameCnf: true,
		},
		{name: "Different Cnf",
			// {"alg":"RS256","typ":"JWT","kid":"1234"}.{"iss":"https://example.com","sub":"123","aud":"abc","cnf":{"jwk":{"alg":"ES256","crv":"P-256","kty":"EC","x":"6hgrwR47GqR6wpeTUAusxBYbwnO5I_B5nTaO0YH75Uk","y":"H0ZtI1Bbytlvfn3ej3eW0qVkXpyuFSRVmuLtwRq3UyM"}},"exp":34,"iat":12,"email":"alice@example.com","nonce":"0x0BEE"}.fakesignature
			t1: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQifQ.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiMTIzIiwiYXVkIjoiYWJjIiwiY25mIjp7Imp3ayI6eyJhbGciOiJFUzI1NiIsImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiNmhncndSNDdHcVI2d3BlVFVBdXN4Qllid25PNUlfQjVuVGFPMFlINzVVayIsInkiOiJIMFp0STFCYnl0bHZmbjNlajNlVzBxVmtYcHl1RlNSVm11THR3UnEzVXlNIn19LCJleHAiOjM0LCJpYXQiOjEyLCJlbWFpbCI6ImFsaWNlQGV4YW1wbGUuY29tIiwibm9uY2UiOiIweDBCRUUifQ.ZmFrZXNpZ25hdHVyZQ",
			// {"alg":"RS256","typ":"JWT","kid":"1234"}.{"iss":"https://example.com","sub":"123","aud":"abc","cnf":{"jwk":{"alg":"ES256","crv":"P-256","kty":"EC","x":"yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy","y":"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}},"exp":35,"iat":14,"email":"alice@example.com","nonce":"0x0BEE"}.fakesignature
			t2:           "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQifQ.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiMTIzIiwiYXVkIjoiYWJjIiwiY25mIjp7Imp3ayI6eyJhbGciOiJFUzI1NiIsImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoieXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eSIsInkiOiJ6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enoifX0sImV4cCI6MzUsImlhdCI6MTQsImVtYWlsIjoiYWxpY2VAZXhhbXBsZS5jb20iLCJub25jZSI6IjB4MEJFRSJ9.ZmFrZXNpZ25hdHVyZQ",
			checkSameCnf: true,
			expCnfErr:    "different cnf claims",
		},
		{name: "Different Cnf (missing Cnf)",
			// {"alg":"RS256","typ":"JWT","kid":"1234"}.{"iss":"https://example.com","sub":"123","aud":"abc","exp":34,"iat":12,"email":"alice@example.com","nonce":"0x0BEE"}.fakesignature
			t1: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQifQ.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiMTIzIiwiYXVkIjoiYWJjIiwiZXhwIjozNCwiaWF0IjoxMiwiZW1haWwiOiJhbGljZUBleGFtcGxlLmNvbSIsIm5vbmNlIjoiMHgwQkVFIn0.ZmFrZXNpZ25hdHVyZQ",
			// {"alg":"RS256","typ":"JWT","kid":"1234"}.{"iss":"https://example.com","sub":"123","aud":"abc","cnf":{"jwk":{"alg":"ES256","crv":"P-256","kty":"EC","x":"yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy","y":"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}},"exp":35,"iat":14,"email":"alice@example.com","nonce":"0x0BEE"}.fakesignature
			t2:           "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQifQ.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiMTIzIiwiYXVkIjoiYWJjIiwiY25mIjp7Imp3ayI6eyJhbGciOiJFUzI1NiIsImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoieXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eSIsInkiOiJ6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enoifX0sImV4cCI6MzUsImlhdCI6MTQsImVtYWlsIjoiYWxpY2VAZXhhbXBsZS5jb20iLCJub25jZSI6IjB4MEJFRSJ9.ZmFrZXNpZ25hdHVyZQ",
			checkSameCnf: true,
			expCnfErr:    "different cnf claims",
		},
		{name: "Both Cnf claims nil case",
			// {"alg":"RS256","typ":"JWT","kid":"1234"}.{"iss":"https://example.com","sub":"123","aud":"abc","exp":34,"iat":12,"email":"alice@example.com","nonce":"0x0BEE"}.fakesignature
			t1: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQifQ.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiMTIzIiwiYXVkIjoiYWJjIiwiZXhwIjozNCwiaWF0IjoxMiwiZW1haWwiOiJhbGljZUBleGFtcGxlLmNvbSIsIm5vbmNlIjoiMHgwQkVFIn0.ZmFrZXNpZ25hdHVyZQ",
			// {"alg":"RS256","typ":"JWT","kid":"1234"}.{"iss":"https://example.com","sub":"123","aud":"abc","exp":35,"iat":12,"email":"alice@example.com"}.fakesignature
			t2:           "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQifQ.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiMTIzIiwiYXVkIjoiYWJjIiwiZXhwIjozNSwiaWF0IjoxMiwiZW1haWwiOiJhbGljZUBleGFtcGxlLmNvbSJ9.ZmFrZXNpZ25hdHVyZQ",
			checkSameCnf: true,
			expCnfErr:    "both tokens have nil cnf claims",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			err := SameIdentity([]byte(tc.t1), []byte(tc.t2))
			if tc.expIdErr != "" {
				require.ErrorContains(t, err, tc.expIdErr)
			} else {
				require.NoError(t, err)
			}

			err = RequireOlder([]byte(tc.t1), []byte(tc.t2))
			if tc.expAgeErr != "" {
				require.ErrorContains(t, err, tc.expAgeErr)
			} else {
				require.NoError(t, err)
			}

			if tc.checkSameCnf {
				err = SameCnf([]byte(tc.t1), []byte(tc.t2))
				if tc.expCnfErr != "" {
					require.ErrorContains(t, err, tc.expCnfErr)
				} else {
					require.NoError(t, err)
				}
			}

		})
	}
}

//go:embed test_jws.json
var test_jws []byte

func TestJwtToJWS(t *testing.T) {
	t.Run("Valid JWT to JWS", func(t *testing.T) {
		jwt, err := NewJwt([]byte("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQifQ.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiMTIzIiwiYXVkIjoiYWJjIiwiZXhwIjozNCwiaWF0IjoxMiwiZW1haWwiOiJhbGljZUBleGFtcGxlLmNvbSIsIm5vbmNlIjoiMHgwQkVFIn0.ZmFrZXNpZ25hdHVyZQ"))
		require.NoError(t, err)

		jws, err := jwt.Jws()
		require.NoError(t, err)
		require.NotNil(t, jws)
		jwsPrettyJson, err := jws.PrettyJson()
		require.NoError(t, err)

		require.Equal(t, string(test_jws), string(jwsPrettyJson))
	})
}
