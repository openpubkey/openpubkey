package pktoken_test

import (
	"crypto"
	_ "embed"
	"encoding/json"
	"fmt"
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
	fmt.Println(string(pktJson))

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

	// Alphabetical order A to Z
	pheaderOpAz := `{"alg":"RS256","typ":"JWT"}`
	pheaderCicAz := `{"alg":"ES256","rz":"872c6399f440d80a8c28935d8dd84da13ecdfc8e99b3dfbf92bdf1a3133a0b5e","typ":"CIC","upk":{"alg":"ES256","crv":"P-256","kty":"EC","x":"1UxCtDCjyb0bSz9P815sMTqGjSdF2u-sYk0egy4yigs","y":"0qQnHkOLMyQY5WwnpjaFO2TzGCtq_nFg10fI16LcexE"}}`
	testUnchangedByCompact(t, payload, pheaderOpAz, pheaderCicAz)

	// Reverse Alphabetical order Z to A
	pheaderOpZa := `{"typ":"JWT","alg":"RS256"}`
	pheaderCicZa := `{"upk":{"alg":"ES256","crv":"P-256","kty":"EC","x":"1UxCtDCjyb0bSz9P815sMTqGjSdF2u-sYk0egy4yigs","y":"0qQnHkOLMyQY5WwnpjaFO2TzGCtq_nFg10fI16LcexE"}, "typ":"CIC", "rz":"872c6399f440d80a8c28935d8dd84da13ecdfc8e99b3dfbf92bdf1a3133a0b5e", "alg":"ES256"}`
	testUnchangedByCompact(t, payload, pheaderOpZa, pheaderCicZa)

	// Whitespace
	pheaderOpWs := `{  "alg":"RS256",     "typ":"JWT" }`
	pheaderCicWs := `{ "alg":    "ES256",  "rz": "872c6399f440d80a8c28935d8dd84da13ecdfc8e99b3dfbf92bdf1a3133a0b5e" , "typ":"CIC","upk":{"alg":"ES256","crv":"P-256","kty":"EC","x":"1UxCtDCjyb0bSz9P815sMTqGjSdF2u-sYk0egy4yigs","y":"0qQnHkOLMyQY5WwnpjaFO2TzGCtq_nFg10fI16LcexE"}}`

	testUnchangedByCompact(t, payload, pheaderOpWs, pheaderCicWs)
	testUnchangedAfterMarshalling(t, payload, pheaderOpWs, pheaderCicWs)
}

func testUnchangedByCompact(t *testing.T, payload string, opPheader string, cicPheader string) {
	pkt := &pktoken.PKToken{}

	// Build OP Token and add it to PK Token
	opTokenOriginal := BuildToken(opPheader, payload, "fakeSignature OP")
	err := pkt.AddSignature(opTokenOriginal, pktoken.OIDC)
	require.NoError(t, err)

	// Check that Compact does not change original OP Token
	opTokenOut, err := pkt.Compact(pkt.Op)
	require.EqualValues(t, string(opTokenOriginal), string(opTokenOut), "danger, signed values in OP Token being changed")

	// Build CIC Token and add it to PK Token
	cicTokenOriginal := BuildToken(cicPheader, payload, "fakeSignature")
	require.NotNil(t, cicTokenOriginal)
	err = pkt.AddSignature(cicTokenOriginal, pktoken.CIC)
	require.NoError(t, err)

	// Check that Compact does not change original CIC Token
	cicTokenCompact, err := pkt.Compact(pkt.Cic)
	require.EqualValues(t, string(cicTokenOriginal), string(cicTokenCompact), "danger, signed values in CIC Token being changed")
}

func testUnchangedAfterMarshalling(t *testing.T, payload string, opPheader string, cicPheader string) {
	pkt := &pktoken.PKToken{}

	// Build OP Token and add it to PK Token
	opTokenOriginal := BuildToken(opPheader, payload, "fakeSignature OP")
	err := pkt.AddSignature(opTokenOriginal, pktoken.OIDC)
	require.NoError(t, err)

	// Build CIC Token and add it to PK Token
	cicTokenOriginal := BuildToken(cicPheader, payload, "fakeSignature")
	err = pkt.AddSignature(cicTokenOriginal, pktoken.CIC)
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
	tokenStr := string(util.Base64EncodeForJWT([]byte(protected)))
	tokenStr += "."
	tokenStr += string(util.Base64EncodeForJWT([]byte(payload)))
	tokenStr += "."
	tokenStr += string(util.Base64EncodeForJWT([]byte(sig)))
	return []byte(tokenStr)
}
