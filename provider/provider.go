package provider

import (
	"context"

	"github.com/awnumar/memguard"
	"github.com/openpubkey/openpubkey/client"
)

// RefreshableOP declares the minimal interface for an OPK OIDC client that
// interacts with an OP (OpenID provider) that allows for its token to be
// refreshed.
type RefreshableOP interface {
	client.OpenIdProvider
	Refresh(ctx context.Context) (*memguard.LockedBuffer, error)
}
