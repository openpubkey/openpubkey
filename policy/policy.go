package policy

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/user"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

// SystemDefaultPolicyPath is the default filepath where opk-ssh policy is
// defined
const SystemDefaultPolicyPath = "/etc/opk/policy.yml"

type User struct {
	// Email is the user's email. It is the expected value used when comparing
	// against an id_token's email claim
	Email string `yaml:"email"`
	// Principals is a list of allowed principals
	Principals []string `yaml:"principals"`
	// Sub        string   `yaml:"sub,omitempty"`
}

// Policy represents an opk-ssh policy
type Policy struct {
	// Users is a list of all user entries in the policy
	Users []User `yaml:"users"`
}

// AddAllowedPrincipal adds a new allowed principal to the user whose email is
// equal to userEmail. If no user can be found with the email userEmail, then a
// new user entry is added with an initial allowed principals list containing
// principal. No changes are made if the principal is already allowed for this
// user.
func (p *Policy) AddAllowedPrincipal(principal string, userEmail string) {
	userExists := false
	if len(p.Users) != 0 {
		// search to see if the current user already has an entry in the policy
		// file
		for i := range p.Users {
			user := &p.Users[i]
			if user.Email == userEmail {
				principalExists := false
				for _, p := range user.Principals {
					// if the principal already exists for this user, then skip
					if p == principal {
						log.Printf("User with email %s already has access under the principal %s, skipping...\n", userEmail, principal)
						principalExists = true
					}
				}

				if !principalExists {
					user.Principals = append(user.Principals, principal)
					log.Printf("Successfully added user with email %s with principal %s to the policy file\n", userEmail, principal)
				}
				userExists = true
			}
		}
	}

	// if the policy is empty or if no user found with userEmail, then create a
	// new entry
	if len(p.Users) == 0 || !userExists {
		newUser := User{
			Email:      userEmail,
			Principals: []string{principal},
		}
		// add the new user to the list of users in the policy
		p.Users = append(p.Users, newUser)
	}
}

// FromYAML decodes YAML encoded input into policy.Policy
func FromYAML(input []byte) (*Policy, error) {
	policy := &Policy{}
	if err := yaml.Unmarshal(input, policy); err != nil {
		return nil, fmt.Errorf("error unmarshalling input to policy.Policy: %w", err)
	}
	return policy, nil
}

// ParsePolicy parses the opk-ssh policy at the policy.SystemDefaultPolicyPath.
// If there is a permission error when reading this file, then the user's local
// policy file (~/.opk/policy.yml) is parsed instead.
//
// If successful, returns the parsed policy and filepath used to read the
// policy. Otherwise, a non-nil error is returned.
func ParsePolicy(username string) (*Policy, string, error) {
	usr, err := user.Lookup(username)
	if err != nil {
		return nil, "", fmt.Errorf("failed to find home directory for the username %v: %w", username, err)
	}

	policyData, policyFilePath, err := GetPolicy(usr.HomeDir)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get policy: %w", err)
	}

	policy, err := FromYAML(policyData)
	if err != nil {
		return nil, "", err
	}

	return policy, policyFilePath, nil
}

// GetPolicy has the same semantics as policy.ParsePolicy except it returns the
// raw YAML instead of parsing the contents into the policy type
func GetPolicy(userHomeDirectory string) ([]byte, string, error) {
	var policyFilePath = SystemDefaultPolicyPath
	// check that the policy.yml file exists (created through configuration
	// script prior to this)
	if _, err := os.Stat(policyFilePath); errors.Is(err, os.ErrNotExist) {
		return nil, "", fmt.Errorf("policy file does not exist at path %s: %w", policyFilePath, err)
	}

	// if the user has root access, the policy file will be /etc/opk/policy.yml
	// else, we will add it to ~/.opk/policy.yml
	policy, err := os.ReadFile(policyFilePath)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "permission denied") {
			policyFilePath = path.Join(userHomeDirectory, ".opk/policy.yml")
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
