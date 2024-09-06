package main

import (
	"context"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestPolicyParse(t *testing.T) {

	providerOpts := providers.DefaultMockProviderOpts()
	op, _, template, err := providers.NewMockProvider(providerOpts)
	require.NoError(t, err)
	template.ExtraClaims = map[string]any{"email": "alice@example.com"}

	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	require.NoError(t, err)
	c, err := client.New(op, client.WithSigner(signer, alg))
	require.NoError(t, err)

	pkt, err := c.Auth(context.Background())
	require.NoError(t, err)

	policyEnforcer := simpleFilePolicyEnforcer{
		PolicyFilePath: "/etc/opk/policy",
		readPolicyFile: func() ([]byte, error) {
			return []byte("alice@example.com test dev"), nil
		},
	}

	err = policyEnforcer.checkPolicy("test", pkt)
	require.NoError(t, err)

	err = policyEnforcer.checkPolicy("dev", pkt)
	require.NoError(t, err)

	err = policyEnforcer.checkPolicy("root", pkt)
	require.ErrorContains(t, err, "no policy to allow")

	policyEnforcer = simpleFilePolicyEnforcer{
		PolicyFilePath: "/etc/opk/policy",
		readPolicyFile: func() ([]byte, error) {
			return []byte("bob@example.com test bob\nalice@example.com test root"), nil
		},
	}

	err = policyEnforcer.checkPolicy("root", pkt)
	require.NoError(t, err)
	err = policyEnforcer.checkPolicy("test", pkt)
	require.NoError(t, err)
	err = policyEnforcer.checkPolicy("bob", pkt)
	require.ErrorContains(t, err, "no policy to allow")

	template.ExtraClaims = map[string]any{"email": "bob@example.com"}
	signer, err = util.GenKeyPair(alg)
	require.NoError(t, err)
	c, err = client.New(op, client.WithSigner(signer, alg))
	require.NoError(t, err)

	pkt2, err := c.Auth(context.Background())
	require.NoError(t, err)

	err = policyEnforcer.checkPolicy("test", pkt2)
	require.NoError(t, err)
	err = policyEnforcer.checkPolicy("bob", pkt2)
	require.NoError(t, err)
	err = policyEnforcer.checkPolicy("root", pkt2)
	require.ErrorContains(t, err, "no policy to allow")

}

func TestPolicyParseFailures(t *testing.T) {

	providerOpts := providers.DefaultMockProviderOpts()
	op, _, template, err := providers.NewMockProvider(providerOpts)
	require.NoError(t, err)
	template.ExtraClaims = map[string]any{"email": "bob@example.com"}

	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	require.NoError(t, err)
	c, err := client.New(op, client.WithSigner(signer, alg))
	require.NoError(t, err)

	pkt, err := c.Auth(context.Background())
	require.NoError(t, err)

	policyEnforcer := simpleFilePolicyEnforcer{
		PolicyFilePath: "/etc/opk/policy",
		readPolicyFile: func() ([]byte, error) {
			return []byte("alice@example.com test dev"), nil
		},
	}

	err = policyEnforcer.checkPolicy("test", pkt)
	require.ErrorContains(t, err, "no policy for email")

	err = policyEnforcer.checkPolicy("dev", pkt)
	require.ErrorContains(t, err, "no policy for email")

	err = policyEnforcer.checkPolicy("root", pkt)
	require.ErrorContains(t, err, "no policy for email")

	policyEnforcer = simpleFilePolicyEnforcer{
		PolicyFilePath: "/etc/opk/policy",
		readPolicyFile: func() ([]byte, error) {
			return nil, nil
		},
	}

	err = policyEnforcer.checkPolicy("test", pkt)
	require.ErrorContains(t, err, "policy file contained no policy")

	policyEnforcer = simpleFilePolicyEnforcer{
		PolicyFilePath: "/etc/opk/policy",
		readPolicyFile: func() ([]byte, error) {
			return []byte(""), nil
		},
	}

	err = policyEnforcer.checkPolicy("test", pkt)
	require.ErrorContains(t, err, "policy file contained no policy")
}
