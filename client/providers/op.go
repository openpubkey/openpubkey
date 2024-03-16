package providers

import (
	"context"
	"crypto"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/client/providers/discover"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/verifier"
)

// Interface for interacting with the OP (OpenID Provider)
type OpenIdProvider interface {
	RequestTokens(ctx context.Context, cic *clientinstance.Claims) ([]byte, error)
	PublicKey(ctx context.Context, headers jws.Headers) (crypto.PublicKey, error)

	PublicKeyByKeyId(ctx context.Context, issuer string, keyID []byte) (*discover.PublicKeyRecord, error)
	PublicKeyByJTK(ctx context.Context, jtk string) (*discover.PublicKeyRecord, error)
	PublicKeyByToken(ctx context.Context, issuer string, token []byte) (*discover.PublicKeyRecord, error)
	Verifier() verifier.ProviderVerifier
}

type BrowserOpenIdProvider interface {
	OpenIdProvider
	HookHTTPSession(h http.HandlerFunc)
}

// We use this to inject our own publicKeyFunc for testing and extensibility.
// For an example of how this works see github_actions_test
type PublicKeyFunc = func(ctx context.Context, headers jws.Headers) (crypto.PublicKey, error)
