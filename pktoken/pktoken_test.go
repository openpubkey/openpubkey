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

package pktoken_test

import (
	"crypto"
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/mocks"
	"github.com/openpubkey/openpubkey/pktoken/simplejws"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/openpubkey/openpubkey/util"
)

func TestPkToken(t *testing.T) {
	alg := jwa.ES256

	signingKey, err := util.GenKeyPair(alg)
	require.NoError(t, err)

	pkt, err := mocks.GenerateMockPKToken(signingKey, alg)
	require.NoError(t, err)

	testPkTokenMessageSigning(t, pkt, signingKey)
	testPkTokenSerialization(t, pkt)
}

func testPkTokenMessageSigning(t *testing.T, pkt *pktoken.PKToken, signingKey crypto.Signer) {
	// Create new OpenPubKey Signed Message (OSM)
	msg := "test message!"
	osm, err := pkt.NewSignedMessage([]byte(msg), signingKey)
	require.NoError(t, err)

	// Verify our OSM is valid
	payload, err := pkt.VerifySignedMessage(osm)
	require.NoError(t, err)

	require.Equal(t, msg, string(payload), "OSM payload did not match what we initially wrapped")
}

func testPkTokenSerialization(t *testing.T, pkt *pktoken.PKToken) {
	// Test json serialization/deserialization
	pktJson, err := json.Marshal(pkt)
	require.NoError(t, err)

	var newPkt *pktoken.PKToken
	err = json.Unmarshal(pktJson, &newPkt)
	require.NoError(t, err)

	newPktJson, err := json.Marshal(newPkt)
	require.NoError(t, err)

	require.JSONEq(t, string(pktJson), string(newPktJson))
}

func TestPkTokenJwsUnchanged(t *testing.T) {
	payload := `{
		"aud": testAud
		"email": "arthur.aardvark@example.com",
		"exp": 1708641372,
		"iat": 1708554972,
		"iss": "me",
		"nonce": "iOqVQfpJsbt4gpcGUX0lJLT82bTm8PU1fwNghiGau0M",
		"sub": "1234567890"
	  }`

	testCases := []struct {
		name         string
		payload      string
		opProtected  string
		cicProtected string
		cosProtected string
	}{
		{name: "with alphabetical order",
			payload:      payload,
			opProtected:  `{"alg":"RS256","typ":"JWT"}`,
			cicProtected: `{"alg":"ES256","rz":"872c6399f440d80a8c28935d8dd84da13ecdfc8e99b3dfbf92bdf1a3133a0b5e","typ":"CIC","upk":{"alg":"ES256","crv":"P-256","kty":"EC","x":"1UxCtDCjyb0bSz9P815sMTqGjSdF2u-sYk0egy4yigs","y":"0qQnHkOLMyQY5WwnpjaFO2TzGCtq_nFg10fI16LcexE"}}`,
			cosProtected: `{"alg":"ES256","auth_time":1708991378,"eid":"1234","exp":1708994978,"iat":1708991378,"iss":"example.com","kid":"1234","nonce":"test-nonce","ruri":"http://localhost:3000","typ":"COS"}`,
		},
		{name: "with reverse alphabetical order",
			payload:      payload,
			opProtected:  `{"typ":"JWT","alg":"RS256"}`,
			cicProtected: `{"upk":{"alg":"ES256","crv":"P-256","kty":"EC","x":"1UxCtDCjyb0bSz9P815sMTqGjSdF2u-sYk0egy4yigs","y":"0qQnHkOLMyQY5WwnpjaFO2TzGCtq_nFg10fI16LcexE"}, "typ":"CIC", "rz":"872c6399f440d80a8c28935d8dd84da13ecdfc8e99b3dfbf92bdf1a3133a0b5e", "alg":"ES256"}`,
			cosProtected: `{"typ":"COS","ruri":"http://localhost:3000","nonce":"test-nonce","kid":"1234","iss":"example.com","iat":1708991378,"exp":1708994978,"eid":"none","auth_time":1708991378,"alg":"ES256"}`,
		},
		{name: "with extra whitespace",
			payload:      payload,
			opProtected:  `{  "alg" : "RS256",     "typ": "JWT" }`,
			cicProtected: `{  "alg" : "ES256",  "rz": "872c6399f440d80a8c28935d8dd84da13ecdfc8e99b3dfbf92bdf1a3133a0b5e" , "typ":"CIC","upk":{"alg":"ES256","crv":"P-256","kty":"EC","x":"1UxCtDCjyb0bSz9P815sMTqGjSdF2u-sYk0egy4yigs","y":"0qQnHkOLMyQY5WwnpjaFO2TzGCtq_nFg10fI16LcexE"}}`,
			cosProtected: `{  "alg" : "ES256",  "auth_time": 1708991378,"eid":"1234","exp":1708994978,"iat":1708991378,"iss":"example.com","kid":"1234","nonce":"test-nonce","ruri":"http://localhost:3000","typ":"COS"}`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testUnchangedByCompact(t, tc.name, tc.payload, tc.opProtected, tc.cicProtected, tc.cosProtected)
			testUnchangedAfterMarshalling(t, tc.name, tc.payload, tc.opProtected, tc.cicProtected, tc.cosProtected)
		})
	}
}

// Once we remove pkt.Compact we can remove this test
func testUnchangedByCompact(t *testing.T, name string, payload string, opPheader string, cicPheader string, cosPheader string) {
	pkt := &pktoken.PKToken{}

	// Build OP Token and add it to PK Token
	opTokenOriginal := BuildToken(opPheader, payload, "fakeSignature OP")
	err := pkt.AddSignature(opTokenOriginal, pktoken.OIDC)
	require.NoError(t, err)

	// Check that Compact does not change original OP Token
	opTokenOut, err := pkt.Compact(pkt.Op)
	require.NoError(t, err)
	require.EqualValues(t, string(opTokenOriginal), string(opTokenOut), "danger, signed values in OP Token being changed")

	// Build CIC Token and add it to PK Token
	cicTokenOriginal := BuildToken(cicPheader, payload, "fakeSignature")
	err = pkt.AddSignature(cicTokenOriginal, pktoken.CIC)
	require.NoError(t, err)

	// Check that Compact does not change original CIC Token
	cicTokenCompact, err := pkt.Compact(pkt.Cic)
	require.NoError(t, err)
	require.EqualValues(t, string(cicTokenOriginal), string(cicTokenCompact), "danger, signed values in CIC Token being changed")

	// Build COS Token and add it to PK Token
	cosTokenOriginal := BuildToken(cosPheader, payload, "fakeSignature")
	err = pkt.AddSignature(cosTokenOriginal, pktoken.COS)
	require.NoError(t, err)

	// Check that Compact does not change original COS Token
	cosTokenCompact, err := pkt.Compact(pkt.Cos)
	require.NoError(t, err)
	require.EqualValues(t, string(cosTokenOriginal), string(cosTokenCompact), "danger, signed values in COS Token being changed")
}

func testUnchangedAfterMarshalling(t *testing.T, name string, payload string, opPheader string, cicPheader string, cosPheader string) {
	pkt := &pktoken.PKToken{}

	// Build OP Token and add it to PK Token
	opTokenOriginal := BuildToken(opPheader, payload, "fakeSignature OP")
	err := pkt.AddSignature(opTokenOriginal, pktoken.OIDC)
	require.NoError(t, err)

	// Build CIC Token and add it to PK Token
	cicTokenOriginal := BuildToken(cicPheader, payload, "fakeSignature")
	err = pkt.AddSignature(cicTokenOriginal, pktoken.CIC)
	require.NoError(t, err)

	// Build CIC Token and add it to PK Token
	cosTokenOriginal := BuildToken(cosPheader, payload, "fakeSignature")
	err = pkt.AddSignature(cosTokenOriginal, pktoken.COS)
	require.NoError(t, err)

	// Check that Marshal PK Token to Json leaves underlying signed values unchanged
	pktJson, err := pkt.MarshalJSON()
	require.NoError(t, err)

	// Unmarshal it into a simple JWS structure to see if the underlying values have changed
	var simpleJWS simplejws.Jws
	err = json.Unmarshal(pktJson, &simpleJWS)
	require.NoError(t, err)

	opTokenUnmarshalled, err := simpleJWS.GetTokenByTyp("JWT") // JWT is the token typ used by the OP Token (ID Token)
	require.NoError(t, err)
	require.EqualValues(t, string(opTokenOriginal), string(opTokenUnmarshalled), "danger, signed values in OP Token being changed during marshalling")

	cicTokenUnmarshalled, err := simpleJWS.GetTokenByTyp("CIC") // CIC is the token typ used by the OP Token (ID Token)
	require.NoError(t, err)
	require.EqualValues(t, string(cicTokenOriginal), string(cicTokenUnmarshalled), "danger, signed values in CIC Token being changed during marshalling")

	cosTokenUnmarshalled, err := simpleJWS.GetTokenByTyp("COS") // COS is the token typ used by the OP Token (ID Token)
	require.NoError(t, err)
	require.EqualValues(t, string(cosTokenOriginal), string(cosTokenUnmarshalled), "danger, signed values in CIC Token being changed during marshalling")
}

//go:embed test_jwk.json
var test_jwk []byte

// based on https://www.rfc-editor.org/rfc/rfc7638.html
func TestThumprintCalculation(t *testing.T) {
	fromRfc := "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	pub, err := jwk.ParseKey(test_jwk)
	if err != nil {
		t.Fatal(err)
	}
	thumb, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	thumbEnc := util.Base64EncodeForJWT(thumb)
	if string(thumbEnc) != fromRfc {
		t.Fatalf("thumbprint %s did not match expected value %s", thumbEnc, fromRfc)
	}
}

func BuildToken(protected string, payload string, sig string) []byte {
	return util.JoinJWTSegments(
		util.Base64EncodeForJWT([]byte(protected)),
		util.Base64EncodeForJWT([]byte(payload)),
		util.Base64EncodeForJWT([]byte(sig)))
}
