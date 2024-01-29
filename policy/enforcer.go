package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"

	"github.com/openpubkey/openpubkey/pktoken"
	"golang.org/x/exp/slices"
)

type Enforcer struct {
	PolicyFilePath string
}

func (p *Enforcer) CheckPolicy(principalDesired string, pkt *pktoken.PKToken) error {
	// read the root policy file
	rootPolicyUsers, err := readPolicyFileUsers("/etc/opk/policy.yml")

	if err != nil {
		return fmt.Errorf("error reading root policy file: %w", err)
	}

	usr, err := user.Lookup(principalDesired)
	if err != nil {
		return fmt.Errorf("failed to find the unix user with name: %v. error: %w", principalDesired, err)
	}

	// read the home directory policy file
	homeDirPolicyUsers, homeDirErr := readPolicyFileUsers(fmt.Sprintf("%v/.opk/policy.yml", usr.HomeDir))

	// if the home directory doesn't exist then only consider the root policy file
	if homeDirErr != nil && !errors.Is(homeDirErr, os.ErrNotExist) {
		return fmt.Errorf("failed reading home directory policy file at ~/.opk/policy.yml: %w", homeDirErr)
	}

	// check if the home directory policy only contains the current user's username
	if err := checkHomeDirPoliciesValidity(homeDirPolicyUsers, principalDesired); err != nil {
		return fmt.Errorf("home directory policy file is invalid: %w", err)
	}

	var claims struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		return fmt.Errorf("error unmarshalling pk token payload: %w", err)
	}

	// append the two list of policies and check
	for _, user := range append(rootPolicyUsers, homeDirPolicyUsers...) {
		// check each entry to see if the user in the claims is included
		if string(claims.Email) == user.Email {
			// if they are, then check if the desired principal is allowed
			if slices.Contains(user.Principals, principalDesired) {
				// access granted
				return nil
			}
		}
	}

	return fmt.Errorf("no policy to allow %s to assume %s, check policy config at /etc/opk/policy.yml or ~/.opk/policy.yml", claims.Email, principalDesired)
}

func readPolicyFileUsers(policyFilePath string) ([]User, error) {
	info, err := os.Stat(policyFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to describe the file at path %s: %w", policyFilePath, err)
	}
	mode := info.Mode()

	// only the owner of this file should be able to write to it
	if mode.Perm() != fs.FileMode(0600) {
		return nil, fmt.Errorf("policy file has insecure permissions, expected (0600), got (%o)", mode.Perm())
	}

	content, err := os.ReadFile(policyFilePath)
	if err != nil {
		return nil, err
	}

	policy, err := FromYAML(content)
	if err != nil {
		return nil, err
	}

	return policy.Users, nil
}

func checkHomeDirPoliciesValidity(users []User, principalDesired string) error {
	for _, user := range users {
		if len(user.Principals) != 1 || user.Principals[0] != principalDesired {
			return fmt.Errorf("principals used in the home directory policy file are invalid")
		}
	}
	return nil
}
