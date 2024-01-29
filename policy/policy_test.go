package policy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/client/providers"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

// copyFile copies the content read from srcFilePath and writes it to a new file
// located at destFilePath. The destination file has the expected permission
// bits set that the policy enforcer requires
func copyFile(t *testing.T, srcFilePath, destFilePath string) {
	input, err := os.ReadFile(srcFilePath)
	require.NoErrorf(t, err, "failed to read source file path %s", srcFilePath)

	err = os.WriteFile(destFilePath, input, 0600)
	require.NoErrorf(t, err, "failed to copy source file to destination path %s", destFilePath)
}

func TestPolicyApproved(t *testing.T) {
	t.Skip()
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

	tempDir := t.TempDir()
	policyFilePath := filepath.Join(tempDir, "policy_test.yml")
	copyFile(t, "./policy_test.yml", policyFilePath)
	policyEnforcer := Enforcer{
		PolicyFilePath: policyFilePath,
	}

	// Check that policy yaml is properly parsed and checked
	if err := policyEnforcer.CheckPolicy("test", pkt); err != nil {
		t.Error(err)
	}
}

func TestPolicyDeniedBadUser(t *testing.T) {
	t.Skip()
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

	tempDir := t.TempDir()
	policyFilePath := filepath.Join(tempDir, "policy_test.yml")
	copyFile(t, "./policy_test.yml", policyFilePath)
	policyEnforcer := Enforcer{
		PolicyFilePath: policyFilePath,
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
	t.Skip()
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

	tempDir := t.TempDir()
	policyFilePath := filepath.Join(tempDir, "policy_test_no_entry.yml")
	copyFile(t, "./policy_test_no_entry.yml", policyFilePath)
	policyEnforcer := Enforcer{
		PolicyFilePath: policyFilePath,
	}

	// Check that policy yaml is properly parsed and that the error is no user entry
	if err := policyEnforcer.CheckPolicy("test", pkt); err != nil {
		fmt.Println(err.Error())
		if !strings.Contains(strings.ToLower(err.Error()), "no policy included for user") {
			t.Error(err)
		}
	}
}
