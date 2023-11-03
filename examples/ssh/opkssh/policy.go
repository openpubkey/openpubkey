package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/openpubkey/openpubkey/pktoken"
	"golang.org/x/exp/slices"
)

type simpleFilePolicyEnforcer struct {
	PolicyFilePath string
}

func (p *simpleFilePolicyEnforcer) readPolicyFile() (string, []string, error) {
	info, err := os.Stat(p.PolicyFilePath)
	if err != nil {
		return "", nil, err
	}
	mode := info.Mode()

	// Only the owner of this file should be able to write to it
	if mode.Perm() != fs.FileMode(0600) {
		return "", nil, fmt.Errorf("policy file has insecure permissions, expected (0600), got (%o)", mode.Perm())
	}

	content, err := os.ReadFile(p.PolicyFilePath)
	if err != nil {
		return "", nil, err
	}
	rows := strings.Split(string(content), "\n")

	for _, row := range rows {
		entries := strings.Fields(row)
		if len(entries) > 1 {
			email := entries[0]
			allowedPrincipals := entries[1:]
			return email, allowedPrincipals, nil
		}
	}
	return "", nil, fmt.Errorf("policy file contained no policy")
}

func (p *simpleFilePolicyEnforcer) checkPolicy(principalDesired string, pkt *pktoken.PKToken) error {
	allowedEmail, allowedPrincipals, err := p.readPolicyFile()
	if err != nil {
		return err
	}
	var claims struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		return err
	}
	if string(claims.Email) == allowedEmail {
		if slices.Contains(allowedPrincipals, principalDesired) {
			// Access granted
			return nil
		} else {
			return fmt.Errorf("no policy to allow %s to assume %s, check policy config in %s", claims.Email, principalDesired, p.PolicyFilePath)
		}
	} else {
		return fmt.Errorf("no policy for email %s, allowed email is %s, check policy config in %s", claims.Email, allowedEmail, p.PolicyFilePath)
	}
}

type policyCheck func(userDesired string, pkt *pktoken.PKToken) error
