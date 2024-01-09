package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path"
	"strings"

	"github.com/openpubkey/openpubkey/pktoken"
	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v3"
)

type User struct {
	Email      string   `yaml:"email"`
	Principals []string `yaml:"principals"`
	// Sub        string   `yaml:"sub,omitempty"`
}

type Users struct {
	// List of all user entries in the policy file
	Users []User `yaml:"users"`
}

type Enforcer struct {
	PolicyFilePath string
}

func (p *Enforcer) CheckPolicy(principalDesired string, pkt *pktoken.PKToken) error {
	// read the root policy file
	rootPolicies, err := readPolicyFile("/etc/opk/policy.yml")

	if err != nil {
		return fmt.Errorf("error reading root policy file: %w", err)
	}

	usr, err := user.Lookup(principalDesired)
	if err != nil {
		return fmt.Errorf("failed to find the unix user with name: %v. error: %w", principalDesired, err)
	}

	// read the home directory policy file
	homeDirPolicies, homeDirErr := readPolicyFile(fmt.Sprintf("%v/.opk/policy.yml", usr.HomeDir))

	// if the home directory doesn't exist then only consider the root policy file
	if homeDirErr != nil && !errors.Is(homeDirErr, os.ErrNotExist) {
		return fmt.Errorf("failed reading home directory policy file at ~/.opk/policy.yml: %w", homeDirErr)
	}

	// check if the home directory policy only contains the current user's username
	if err := checkHomeDirPoliciesValidity(homeDirPolicies, principalDesired); err != nil {
		return fmt.Errorf("home directory policy file is invalid: %w", err)
	}

	var claims struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		return fmt.Errorf("error unmarshalling pk token payload: %w", err)
	}

	// append the two list of policies and check
	for _, policy := range append(rootPolicies, homeDirPolicies...) {
		// check each entry to see if the user in the claims is included
		if string(claims.Email) == policy.Email {
			// if they are, then check if the desired principal is allowed
			if slices.Contains(policy.Principals, principalDesired) {
				// access granted
				return nil
			}
		}
	}

	return fmt.Errorf("no policy to allow %s to assume %s, check policy config at /etc/opk/policy.yml or ~/.opk/policy.yml", claims.Email, principalDesired)
}

func GetPolicy(inputPrincipal string, homeDirectory string) ([]byte, string, error) {
	var policyFilePath = "/etc/opk/policy.yml"
	// check that the policy.yml file exists (created through configuration script prior to this)
	if _, err := os.Stat(policyFilePath); errors.Is(err, os.ErrNotExist) {
		return nil, "", fmt.Errorf("policy file does not exist at path %s: %w", policyFilePath, err)
	}

	// if the user has root access, the policy file will be /etc/opk/policy.yml
	// else, we will add it to ~/.opk/policy.yml
	policy, err := os.ReadFile(policyFilePath)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "permission denied") {
			policyFilePath = path.Join(homeDirectory, ".opk/policy.yml")
			// if we're accessing as non-root, check that /home/{input_principal}/policy.yml exists
			// it should be created when the user runs zli configure as a non-root user
			if _, err := os.Stat(policyFilePath); errors.Is(err, os.ErrNotExist) {
				return nil, "", fmt.Errorf("policy file does not exist at path %s: %w", policyFilePath, err)
			}

			// extract the policy from this user's personal policy file
			if policy, err = os.ReadFile(policyFilePath); err != nil {
				return nil, "", fmt.Errorf("failed to read policy at path %s: %w", policyFilePath, err)
			}
			return policy, policyFilePath, nil
		}
		return nil, "", fmt.Errorf("failed to read the policy file with err: %w", err)
	}

	// if no error, then default to returning the root policy
	return policy, policyFilePath, nil
}

func readPolicyFile(policyFilePath string) ([]User, error) {
	info, err := os.Stat(policyFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to describe the file at path: %w", err)
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

	users := Users{}
	if err := yaml.Unmarshal([]byte(content), &users); err != nil {
		return nil, err
	}

	return users.Users, nil
}

func checkHomeDirPoliciesValidity(policies []User, principalDesired string) error {
	for _, policy := range policies {
		if len(policy.Principals) != 1 || policy.Principals[0] != principalDesired {
			return fmt.Errorf("principals used in the home directory policy file are invalid")
		}
	}
	return nil
}
