package providers

import (
	"context"
	"crypto"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/util"
)

func TestPublicKeyResolver(t *testing.T) {
	provider, _ := NewMockOpenIdProvider()
	alg := jwa.RS256
	signingKey, err := util.GenKeyPair(alg)
	if err != nil {
		t.Fatal(err)
	}
	resolver := func(ctx context.Context, idt []byte) (crypto.PublicKey, error) {
		return signingKey.Public(), nil
	}
	wrapped := WithPublicKeyResolver(provider, nil)
	_, e := wrapped.PublicKey(context.Background(), []byte{})
	if e == nil {
		t.Fatal("Expected error")
	}
	wrapped = WithPublicKeyResolver(provider, resolver)
	p, _ := wrapped.PublicKey(context.Background(), []byte{})
	if p != signingKey.Public() {
		t.Fatal("Unexpected public key")
	}
	s, _ := provider.PublicKey(context.Background(), []byte{})
	if p == s {
		t.Fatal("Unexpected public key")
	}
}
