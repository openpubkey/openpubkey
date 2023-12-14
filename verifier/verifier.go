package verifier

import (
	"context"

	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/pktoken"
)

type Allowlist struct {
	AllowedProviders []client.OpenIdProvider
	AllowedCosigners []client.CosignerProvider
}

type VerEvent struct {
	AllowedProviders []client.OpenIdProvider
	AllowedCosigners []client.CosignerProvider
}

type PKTokenVerifier struct {
	Allowlists []Allowlist
	Cache      bool
	Events     []VerEvent
}

func New(allowlist Allowlist) *PKTokenVerifier {
	return &PKTokenVerifier{
		Allowlists: []Allowlist{allowlist},
		Cache:      false,
		Events:     []VerEvent{},
	}
}

func (v PKTokenVerifier) Verify(ctx context.Context, pkt *pktoken.PKToken) error {
	return client.PKTokenVerifer{}.Verify(ctx, pkt)
}

// allowlist := &Allowlist{
// 	AllowedProviders: []oidc.OpenIdProvider{opGoogle, ...},
// 	AllowedCosigners: []cos.CosignerProvider{mfaCosigner, ...},
// }
// verPkt := pktokenverifier.New(ctx, allowlist)
// err = verPkt.Verify(pkt)
