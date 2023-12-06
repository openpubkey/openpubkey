package providers

import (
	"context"
	"crypto"
	"fmt"

	"github.com/openpubkey/openpubkey/client"
)

type PublicKeyResolver func(context.Context, []byte) (crypto.PublicKey, error)

type publicKeyResolver struct {
	client.OpenIdProvider
	resolver PublicKeyResolver
}

func WithPublicKeyResolver(provider client.OpenIdProvider, resolver PublicKeyResolver) client.OpenIdProvider {
	return &publicKeyResolver{
		OpenIdProvider: provider,
		resolver:       resolver,
	}
}

func (e *publicKeyResolver) PublicKey(ctx context.Context, idt []byte) (crypto.PublicKey, error) {
	if e.resolver == nil {
		return nil, fmt.Errorf("resolver is nil")
	}
	return e.resolver(ctx, idt)
}
