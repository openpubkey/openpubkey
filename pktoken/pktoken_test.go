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

package pktoken_test

import (
	"crypto"
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/mocks"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/openpubkey/openpubkey/util"
)

func TestPkToken(t *testing.T) {
	alg := jwa.ES256

	signingKey, err := util.GenKeyPair(alg)
	if err != nil {
		t.Fatal(err)
	}

	pkt, err := mocks.GenerateMockPKToken(t, signingKey, alg)
	if err != nil {
		t.Fatal(err)
	}

	testPkTokenMessageSigning(t, pkt, signingKey)
	testPkTokenSerialization(t, pkt)
}

func testPkTokenMessageSigning(t *testing.T, pkt *pktoken.PKToken, signingKey crypto.Signer) {
	// Create new OpenPubKey Signed Message (OSM)
	msg := "test message!"
	osm, err := pkt.NewSignedMessage([]byte(msg), signingKey)
	if err != nil {
		t.Fatal(err)
	}

	// Verify our OSM is valid
	payload, err := pkt.VerifySignedMessage(osm)
	if err != nil {
		t.Fatal(err)
	}

	if string(payload) != msg {
		t.Fatal("OSM payload did not match what we initially wrapped")
	}
}

func testPkTokenSerialization(t *testing.T, pkt *pktoken.PKToken) {
	// Test json serialization/deserialization
	pktJson, err := json.Marshal(pkt)
	if err != nil {
		t.Fatal(err)
	}

	var newPkt *pktoken.PKToken
	if err := json.Unmarshal(pktJson, &newPkt); err != nil {
		t.Fatal(err)
	}

	newPktJson, err := json.Marshal(newPkt)
	if err != nil {
		t.Fatal(err)
	}

	require.JSONEq(t, string(pktJson), string(newPktJson))
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

func TestJktInPublicHEader(t *testing.T) {
	fromRfc := "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

	// Add create thumbprint
	keyJwk, err := jwk.ParseKey(test_jwk)
	require.NoError(t, err)
	pubJwk, err := keyJwk.PublicKey()
	require.NoError(t, err)
	var pubRaw interface{}
	err = pubJwk.Raw(&pubRaw)
	require.NoError(t, err)

	alg := jwa.ES256
	signingKey, err := util.GenKeyPair(alg)
	require.NoError(t, err)

	pkt, err := mocks.GenerateMockPKToken(signingKey, alg)
	require.NoError(t, err)

	// Add to public header
	err = pkt.AddJKTHeader(pubRaw)
	require.NoError(t, err)

	publicHeadersJson, err := pkt.Op.PublicHeaders().MarshalJSON()
	require.NoError(t, err)
	jktStruct := struct {
		Jkt string `json:"jkt"`
	}{}
	err = json.Unmarshal(publicHeadersJson, &jktStruct)
	require.NoError(t, err)
	require.Equal(t, fromRfc, jktStruct.Jkt, "jkt in public headers does not match value we supplied")
}
