package parties

import (
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/util"
)

func TestSigner(t *testing.T) {
	alg := jwa.ES256

	testCases := []struct {
		name string
		gq   bool
	}{
		{name: "without GQ", gq: false},
		{name: "with GQ", gq: true},
	}

	op, err := NewMockOpenIdProvider()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range testCases {
		signer, err := util.GenKeyPair(alg)
		if err != nil {
			t.Fatal(err)
		}

		client := OpkClient{
			Op: op,
		}

		pkt, nil := client.OidcAuth(signer, alg, map[string]any{}, tc.gq)
		if err != nil {
			t.Fatal(err)
		}

		if tc.gq {
			// Verify our GQ signature
			idt := pkt.OpJWSCompact()
			opPubKey, err := op.PublicKey(idt)
			if err != nil {
				t.Fatal(err)
			}

			sv := gq.NewSignerVerifier(opPubKey.(*rsa.PublicKey), gqSecurityParameter)
			ok := sv.VerifyJWT(idt)
			if !ok {
				t.Fatal(fmt.Errorf("error verifying OP GQ signature on PK Token (ID Token invalid)"))
			}
		}
	}
}
