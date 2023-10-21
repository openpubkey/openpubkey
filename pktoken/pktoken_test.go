package pktoken_test

import (
	"crypto"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/mocks"

	"github.com/lestrrat-go/jwx/v2/jwa"

	"github.com/openpubkey/openpubkey/util"
)

func TestPkToken(t *testing.T) {
	alg := jwa.ES256

	signingKey, err := util.GenKeyPair(alg)
	if err != nil {
		t.Fatal(err)
	}

	pkt, err := mocks.GenerateMockPKToken(signingKey, alg)
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
