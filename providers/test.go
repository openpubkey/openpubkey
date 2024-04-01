package providers

import (
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

// TODO: This code is duplicated in mocks to avoid circular dependencies. When we solve this circular dependencies remove this and point to mocks.
// Tracked in: https://github.com/openpubkey/openpubkey/issues/162
func genCIC(t *testing.T) *clientinstance.Claims {
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	require.NoError(t, err)
	jwkKey, err := jwk.PublicKeyOf(signer)
	require.NoError(t, err)
	err = jwkKey.Set(jwk.AlgorithmKey, alg)
	require.NoError(t, err)
	cic, err := clientinstance.NewClaims(jwkKey, map[string]any{})
	require.NoError(t, err)
	return cic
}
