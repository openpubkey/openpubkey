package policy

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/client/providers"
	"github.com/openpubkey/openpubkey/util"
)

func TestPolicyApproved(t *testing.T) {
	alg := jwa.ES256

	signer, err := util.GenKeyPair(alg)
	if err != nil {
		t.Fatal(err)
	}

	op, err := providers.NewMockOpenIdProvider()
	if err != nil {
		t.Fatal(err)
	}

	client := &client.OpkClient{
		Op: op,
	}

	pkt, err := client.OidcAuth(context.Background(), signer, alg, map[string]any{}, false)
	if err != nil {
		t.Error(err)
	}

	policyEnforcer := Enforcer{
		PolicyFilePath: "./policy_test.yml",
	}

	// Check that policy yaml is properly parsed and checked
	if err := policyEnforcer.CheckPolicy("test", pkt); err != nil {
		t.Error(err)
	}
}

func TestPolicyDeniedBadUser(t *testing.T) {
	alg := jwa.ES256

	signer, err := util.GenKeyPair(alg)
	if err != nil {
		t.Fatal(err)
	}

	op, err := providers.NewMockOpenIdProvider()
	if err != nil {
		t.Fatal(err)
	}

	client := &client.OpkClient{
		Op: op,
	}

	pkt, err := client.OidcAuth(context.Background(), signer, alg, map[string]any{}, false)
	if err != nil {
		t.Error(err)
	}

	policyEnforcer := Enforcer{
		PolicyFilePath: "./policy_test.yml",
	}

	// Check that policy yaml is properly parsed and checked
	if err := policyEnforcer.CheckPolicy("baduser", pkt); err != nil {
		fmt.Println(err.Error())
		if !strings.Contains(strings.ToLower(err.Error()), "no policy to allow") {
			t.Error(err)
		}
	}
}

func TestPolicyDeniedNoUserEntry(t *testing.T) {
	alg := jwa.ES256

	signer, err := util.GenKeyPair(alg)
	if err != nil {
		t.Fatal(err)
	}

	op, err := providers.NewMockOpenIdProvider()
	if err != nil {
		t.Fatal(err)
	}

	client := &client.OpkClient{
		Op: op,
	}

	pkt, err := client.OidcAuth(context.Background(), signer, alg, map[string]any{}, false)
	if err != nil {
		t.Error(err)
	}

	policyEnforcer := Enforcer{
		PolicyFilePath: "./policy_test_no_entry.yml",
	}

	// Check that policy yaml is properly parsed and that the error is no user entry
	if err := policyEnforcer.CheckPolicy("test", pkt); err != nil {
		fmt.Println(err.Error())
		if !strings.Contains(strings.ToLower(err.Error()), "no policy included for user") {
			t.Error(err)
		}
	}
}
