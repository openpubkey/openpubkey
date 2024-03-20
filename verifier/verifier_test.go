package verifier_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/client/mocks"
	"github.com/openpubkey/openpubkey/client/providers/discover"
	"github.com/openpubkey/openpubkey/verifier"
	"github.com/stretchr/testify/require"
)

func TestVerifier(t *testing.T) {
	clientID := "verifier"
	commitmentClaim := "nonce"
	provider, err := mocks.NewMockOpenIdProvider(t, map[string]any{
		"aud": clientID,
	})
	require.NoError(t, err)

	providerGQ, err := mocks.NewMockOpenIdProvider(t, map[string]any{
		"aud": clientID,
	}, mocks.UseGQSign(true))
	require.NoError(t, err)

	opkClient, err := client.New(provider)
	require.NoError(t, err)
	pkt, err := opkClient.Auth(context.Background())
	require.NoError(t, err)

	// The below vanilla check is redundant since there is a final verification step as part of the PK token issuance
	pktVerifier, err := verifier.New(provider.Verifier())
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	require.NoError(t, err)

	// Check if verification fails with incorrect issuer
	wrongIssuer := "https://evil.com/"
	providerVerifier := verifier.NewProviderVerifier(wrongIssuer, commitmentClaim, verifier.ProviderVerifierOpts{SkipClientIDCheck: true})
	pktVerifier, err = verifier.New(providerVerifier)
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	require.Error(t, err)

	// Check if verification fails with incorrect commitment claim
	wrongCommitmentClaim := "evil"
	providerVerifier = verifier.NewProviderVerifier(provider.Verifier().Issuer(), wrongCommitmentClaim, verifier.ProviderVerifierOpts{SkipClientIDCheck: true})
	pktVerifier, err = verifier.New(providerVerifier)
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	require.Error(t, err)

	// When "aud" claim is a single string, check that Client ID is verified when specified correctly
	providerVerifier = verifier.NewProviderVerifier(provider.Verifier().Issuer(), commitmentClaim, verifier.ProviderVerifierOpts{ClientID: clientID})
	pktVerifier, err = verifier.New(providerVerifier)
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	require.NoError(t, err)

	// When "aud" claim is a single string, check that an incorrect Client ID when specified, fails
	wrongClientID := "super_evil"
	providerVerifier = verifier.NewProviderVerifier(provider.Verifier().Issuer(), commitmentClaim, verifier.ProviderVerifierOpts{ClientID: wrongClientID})
	pktVerifier, err = verifier.New(providerVerifier)
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	require.Error(t, err)

	// If audience is a list of strings, make sure verification holds
	provider, err = mocks.NewMockOpenIdProvider(t, map[string]any{
		"aud": []string{clientID},
	})
	require.NoError(t, err)

	opkClient, err = client.New(provider)
	require.NoError(t, err)
	pkt, err = opkClient.Auth(context.Background())
	require.NoError(t, err)

	// When "aud" claim is a list of strings, check that Client ID is verified when specified correctly
	providerVerifier = verifier.NewProviderVerifier(provider.Verifier().Issuer(), commitmentClaim, verifier.ProviderVerifierOpts{ClientID: clientID})
	pktVerifier, err = verifier.New(providerVerifier)
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	require.NoError(t, err)

	// When "aud" claim is a list of strings, check that an incorrect Client ID when specified, fails
	providerVerifier = verifier.NewProviderVerifier(provider.Verifier().Issuer(), commitmentClaim, verifier.ProviderVerifierOpts{ClientID: wrongClientID})
	pktVerifier, err = verifier.New(providerVerifier)
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	require.Error(t, err)

	// Specify a custom public key discoverer that returns the incorrect key and check that verification fails
	alg := jwa.RS256
	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwksFunc, err := discover.MockGetJwksByIssuerOneKey(signer.Public(), pkt.Op.ProtectedHeaders().KeyID(), string(alg))
	require.NoError(t, err)

	providerVerifier = verifier.NewProviderVerifier(provider.Verifier().Issuer(), commitmentClaim, verifier.ProviderVerifierOpts{
		ClientID: clientID,
		DiscoverPublicKey: &discover.PublicKeyFinder{
			JwksFunc: jwksFunc,
		},
	})
	pktVerifier, err = verifier.New(providerVerifier)
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	require.Error(t, err)

	// When the PK token does not have a GQ signature but only GQ signatures are allowed, check that verification fails
	providerVerifier = verifier.NewProviderVerifier(provider.Verifier().Issuer(), commitmentClaim, verifier.ProviderVerifierOpts{})
	pktVerifier, err = verifier.New(providerVerifier)
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt, verifier.GQOnly())
	require.Error(t, err)

	// When the PK token has a GQ signature and only GQ signatures are allowed, check that verification succeeds
	opkClient, err = client.New(providerGQ)
	require.NoError(t, err)
	pkt, err = opkClient.Auth(context.Background())
	require.NoError(t, err)

	providerVerifier = verifier.NewProviderVerifier(providerGQ.Verifier().Issuer(), commitmentClaim, verifier.ProviderVerifierOpts{ClientID: clientID})
	pktVerifier, err = verifier.New(providerVerifier)
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt, verifier.GQOnly())
	require.NoError(t, err)
}
