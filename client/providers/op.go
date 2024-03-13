package providers

import (
	"context"
	"crypto"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/verifier"
)

// Interface for interacting with the OP (OpenID Provider)
type OpenIdProvider interface {
	RequestTokens(ctx context.Context, cic *clientinstance.Claims) ([]byte, error)
	PublicKey(ctx context.Context, headers jws.Headers) (crypto.PublicKey, error)
	Verifier() verifier.ProviderVerifier
}

type BrowserOpenIdProvider interface {
	OpenIdProvider
	HookHTTPSession(h http.HandlerFunc)
}
