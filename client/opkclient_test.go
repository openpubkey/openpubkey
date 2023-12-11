package client_test

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/client/providers"
	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
)

func TestClient(t *testing.T) {
	alg := jwa.ES256

	testCases := []struct {
		name string
		gq   bool
	}{
		{name: "without GQ", gq: false},
		{name: "with GQ", gq: true},
	}

	op, err := providers.NewMockOpenIdProvider()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range testCases {
		signer, err := util.GenKeyPair(alg)
		if err != nil {
			t.Fatal(err)
		}

		c := client.OpkClient{
			Op: op,
		}

		pkt, err := c.OidcAuth(context.Background(), signer, alg, map[string]any{}, tc.gq)
		if err != nil {
			t.Fatal(err)
		}
		jkt, ok := pkt.Op.PublicHeaders().Get("jkt")
		if !ok {
			t.Fatal(fmt.Errorf("missing jkt header"))
		}
		var jktstr string
		if data, ok := jkt.([]uint8); ok {
			jktstr = string(data)
		}

		pubkey, err := op.PublicKey(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := jwk.FromRaw(pubkey)
		if err != nil {
			t.Fatal(err)
		}
		thumbprint, err := pub.Thumbprint(crypto.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		thumbprintStr := string(util.Base64EncodeForJWT(thumbprint))
		if jktstr != thumbprintStr {
			t.Fatal(fmt.Errorf("jkt header %s does not match op thumbprint %s", jkt, thumbprintStr))
		}
		sigType, ok := pkt.ProviderSignatureType()
		if !ok {
			t.Fatal(fmt.Errorf("missing provider type"))
		}

		if sigType == pktoken.Gq {
			// Verify our GQ signature
			idt, err := pkt.Compact(pkt.Op)
			if err != nil {
				t.Fatal(err)
			}

			opPubKey, err := op.PublicKey(context.Background(), idt)
			if err != nil {
				t.Fatal(err)
			}

			sv, err := gq.NewSignerVerifier(opPubKey.(*rsa.PublicKey), client.GQSecurityParameter)
			if err != nil {
				t.Fatal(err)
			}
			ok := sv.VerifyJWT(idt)
			if !ok {
				t.Fatal(fmt.Errorf("error verifying OP GQ signature on PK Token (ID Token invalid)"))
			}
		}
	}
}
