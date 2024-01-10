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
		t.Run(tc.name, func(t *testing.T) {
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
				t.Fatal("missing jkt header")
			}
			data, ok := jkt.([]byte)
			if !ok {
				t.Fatalf("expected jkt header to be a []byte, got %T", jkt)
			}
			jktstr := string(data)

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
				t.Errorf("jkt header %s does not match op thumbprint %s", jkt, thumbprintStr)
			}

			alg, ok := pkt.ProviderAlgorithm()
			if !ok {
				t.Fatal(fmt.Errorf("missing algorithm"))
			}

			if tc.gq {
				if alg != gq.GQ256 {
					t.Errorf("expected GQ256 alg when signing with GQ, got %s", alg)
				}

				// Verify our GQ signature
				idt, err := pkt.Compact(pkt.Op)
				if err != nil {
					t.Fatal(err)
				}

				opPubKey, err := op.PublicKey(context.Background(), nil)
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
			} else {
				if alg != jwa.RS256 {
					t.Errorf("expected RS256 alg when not signing with GQ, got %s", alg)
				}
			}
		})
	}
}
