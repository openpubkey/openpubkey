package verifier_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/client/mocks"
	"github.com/openpubkey/openpubkey/verifier"
)

func TestVerifier(t *testing.T) {
	clientID := "verifier"
	commitmentClaim := "nonce"
	provider, err := mocks.NewMockOpenIdProvider(t, map[string]any{
		"aud": clientID,
	})
	if err != nil {
		t.Fatal(err)
	}

	opkClient, err := client.New(provider)
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := opkClient.Auth(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// The below vanilla check is redundant since there is a final verification step as part of the PK token issuance
	pktVerifier := verifier.New(provider.Verifier())
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	if err != nil {
		t.Fatal(err)
	}

	// Check if verification fails with incorrect issuer
	wrongIssuer := "https://evil.com/"
	providerVerifier := verifier.NewProviderVerifier(wrongIssuer, commitmentClaim, verifier.ProviderVerifierOpts{})
	pktVerifier = verifier.New(providerVerifier)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	if err == nil {
		t.Fatal(err)
	}

	// Check if verification failes with incorrect commitment claim
	wrongCommitmentClaim := "evil"
	providerVerifier = verifier.NewProviderVerifier(provider.Verifier().Issuer(), wrongCommitmentClaim, verifier.ProviderVerifierOpts{})
	pktVerifier = verifier.New(providerVerifier)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	if err == nil {
		t.Fatal(err)
	}

	// When "aud" claim is a single string, check that Client ID is verified when specified correctly
	providerVerifier = verifier.NewProviderVerifier(provider.Verifier().Issuer(), commitmentClaim, verifier.ProviderVerifierOpts{ClientID: clientID})
	pktVerifier = verifier.New(providerVerifier)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	if err != nil {
		t.Fatal(err)
	}

	// When "aud" claim is a single string, check that an incorrect Client ID when specified, fails
	wrongClientID := "super_evil"
	providerVerifier = verifier.NewProviderVerifier(provider.Verifier().Issuer(), commitmentClaim, verifier.ProviderVerifierOpts{ClientID: wrongClientID})
	pktVerifier = verifier.New(providerVerifier)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	if err == nil {
		t.Fatal(err)
	}

	// If audience is a list of strings, make sure verification holds
	provider, err = mocks.NewMockOpenIdProvider(t, map[string]any{
		"aud": []string{clientID},
	})
	if err != nil {
		t.Fatal(err)
	}

	opkClient, err = client.New(provider)
	if err != nil {
		t.Fatal(err)
	}
	pkt, err = opkClient.Auth(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// When "aud" claim is a list of strings, check that Client ID is verified when specified correctly
	providerVerifier = verifier.NewProviderVerifier(provider.Verifier().Issuer(), commitmentClaim, verifier.ProviderVerifierOpts{ClientID: clientID})
	pktVerifier = verifier.New(providerVerifier)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	if err != nil {
		t.Fatal(err)
	}

	// When "aud" claim is a list of strings, check that an incorrect Client ID when specified, fails
	providerVerifier = verifier.NewProviderVerifier(provider.Verifier().Issuer(), commitmentClaim, verifier.ProviderVerifierOpts{ClientID: wrongClientID})
	pktVerifier = verifier.New(providerVerifier)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	if err == nil {
		t.Fatal(err)
	}

	// Specify a custom public key discoverer that returns the incorrect key and check that verification fails
	customKeyDiscoverer := func(ctx context.Context, kid string, issuer string) (jwk.Key, error) {
		alg := jwa.RS256
		signer, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}

		jwkKey, err := jwk.PublicKeyOf(signer)
		if err != nil {
			return nil, err
		}
		jwkKey.Set(jwk.AlgorithmKey, alg)
		jwkKey.Set(jwk.KeyIDKey, kid)

		return jwkKey, nil
	}
	providerVerifier = verifier.NewProviderVerifier(provider.Verifier().Issuer(), commitmentClaim, verifier.ProviderVerifierOpts{
		ClientID:          clientID,
		DiscoverPublicKey: customKeyDiscoverer,
	})
	pktVerifier = verifier.New(providerVerifier)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	if err == nil {
		t.Fatal(err)
	}

	// When the PK token does not have a GQ signature but only GQ signatures are allowed, check that verification fails
	providerVerifier = verifier.NewProviderVerifier(provider.Verifier().Issuer(), commitmentClaim, verifier.ProviderVerifierOpts{})
	pktVerifier = verifier.New(providerVerifier)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt, verifier.GQOnly())
	if err == nil {
		t.Fatal(err)
	}

	// When the PK token has a GQ signature and only GQ signatures are allowed, check that verification succeeds
	opkClient, err = client.New(provider, client.WithSignGQ(true))
	if err != nil {
		t.Fatal(err)
	}
	pkt, err = opkClient.Auth(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	providerVerifier = verifier.NewProviderVerifier(provider.Verifier().Issuer(), commitmentClaim, verifier.ProviderVerifierOpts{})
	pktVerifier = verifier.New(providerVerifier)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt, verifier.GQOnly())
	if err != nil {
		t.Fatal(err)
	}
}
