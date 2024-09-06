// Copyright 2024 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

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
	readPolicyFile FilePolicyReader
}

type FilePolicyReader func() ([]byte, error)

func NewSimpleFilePolicyEnforcer(policyFilePath string) *simpleFilePolicyEnforcer {
	return &simpleFilePolicyEnforcer{
		PolicyFilePath: policyFilePath,
		readPolicyFile: func() ([]byte, error) {
			info, err := os.Stat(policyFilePath)
			if err != nil {
				return nil, err
			}
			mode := info.Mode()

			// Only the owner of this file should be able to write to it
			if mode.Perm() != fs.FileMode(0600) {
				return nil, fmt.Errorf("policy file has insecure permissions, expected (0600), got (%o)", mode.Perm())
			}

			content, err := os.ReadFile(policyFilePath)
			if err != nil {
				return nil, err
			}
			return content, nil
		},
	}
}

func (p *simpleFilePolicyEnforcer) parsePolicyFile() (map[string][]string, error) {
	content, err := p.readPolicyFile()
	if err != nil {
		return nil, err
	}
	rows := strings.Split(string(content), "\n")

	policy := make(map[string][]string)
	for _, row := range rows {
		entries := strings.Fields(row)
		if len(entries) > 1 {
			email := entries[0]
			allowedPrincipals := entries[1:]
			policy[email] = allowedPrincipals
		}
	}
	if len(policy) == 0 {
		return nil, fmt.Errorf("policy file contained no policy")
	}
	return policy, nil
}

func (p *simpleFilePolicyEnforcer) checkPolicy(principalDesired string, pkt *pktoken.PKToken) error {
	// AllowedEmail-->[allowedPrincipals]
	policy, err := p.parsePolicyFile()
	if err != nil {
		return err
	}
	var claims struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		return err
	}

	if policy[claims.Email] != nil {
		allowedPrincipals := policy[claims.Email]
		if slices.Contains(allowedPrincipals, principalDesired) {
			// Access granted
			return nil
		} else {
			return fmt.Errorf("no policy to allow %s to assume %s, check policy config in %s", claims.Email, principalDesired, p.PolicyFilePath)
		}
	} else {
		return fmt.Errorf("no policy for email %s, check policy config in %s", claims.Email, p.PolicyFilePath)
	}
}

type policyCheck func(userDesired string, pkt *pktoken.PKToken) error
