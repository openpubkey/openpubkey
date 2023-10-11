package pktoken_test

import (
	"testing"

	"github.com/openpubkey/openpubkey/pktoken/mocks"
	"github.com/openpubkey/openpubkey/signer"
)

func TestPkToken(t *testing.T) {
	signer, err := signer.NewECDSASigner()
	if err != nil {
		t.Fatal(err)
	}

	pkt, err := mocks.GenerateMockPKToken(signer)
	if err != nil {
		t.Fatal(err)
	}

	// Create new OpenPubKey Signed Message (OSM)
	msg := "test message!"
	osm, err := pkt.NewSignedMessage([]byte(msg), signer.SigningKey())
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
