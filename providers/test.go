package providers

import (
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func GenCIC(t *testing.T) *clientinstance.Claims {
	return GenCICExtra(t, map[string]any{})
}

func GenCICExtra(t *testing.T, extraClaims map[string]any) *clientinstance.Claims {
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	require.NoError(t, err)
	jwkKey, err := jwk.PublicKeyOf(signer)
	require.NoError(t, err)
	err = jwkKey.Set(jwk.AlgorithmKey, alg)
	require.NoError(t, err)
	cic, err := clientinstance.NewClaims(jwkKey, extraClaims)
	require.NoError(t, err)
	return cic
}
