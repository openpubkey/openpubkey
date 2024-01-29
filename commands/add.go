package commands

import (
	"fmt"
	"os"

	"github.com/bastionzero/opk-ssh/policy"
	"gopkg.in/yaml.v3"
)

// AddCmd provides functionality to read and update the opk-ssh policy file
type AddCmd struct{}

// Add adds a new allowed principal to the user whose email is equal to
// userEmail. The current policy file is read and modified.
//
// If successful, returns the policy filepath updated. Otherwise, returns a
// non-nil error
func (a *AddCmd) Add(userEmail string, principal string) (string, error) {
	// Read current policy
	currentPolicy, policyFilePath, err := policy.ParsePolicy(principal)
	if err != nil {
		return "", fmt.Errorf("failed to parse current policy: %w", err)
	}

	// Update policy
	currentPolicy.AddAllowedPrincipal(principal, userEmail)

	// Write to disk
	marshaledData, err := yaml.Marshal(currentPolicy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal updated policy: %w", err)
	}
	if err := os.WriteFile(policyFilePath, marshaledData, 0); err != nil {
		return "", fmt.Errorf("failed to write to policy file %v: %w", policyFilePath, err)
	}

	return policyFilePath, nil
}
