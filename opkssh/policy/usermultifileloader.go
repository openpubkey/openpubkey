// Copyright 2025 OpenPubkey
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

package policy

import (
	"errors"
	"log"
	"os/exec"
	"path"
	"strings"
)

var _ Loader = &UserMultiFileLoader{}

// FileSource implements policy.Source by returning a string that is expected to
// be a filepath
type FileSource string

func (s FileSource) Source() string {
	return string(s)
}

// UserMultiFileLoader implements policy.Loader by reading both the system default
// policy (root policy) and user policy (~/.opk/auth_id where ~ maps to
// Username's home directory)
type UserMultiFileLoader struct {
	*UserPolicyLoader
	LoadWithScript bool
	Username       string
}

func (l *UserMultiFileLoader) Load() (*Policy, Source, error) {
	policy := new(Policy)

	// Try to load the root policy
	rootPolicy, rootPolicyErr := l.LoadSystemDefaultPolicy()
	if rootPolicyErr != nil {
		log.Println("warning: failed to load system default policy:", rootPolicyErr)
	}

	// Try to load the user policy
	userPolicy, userPolicyFilePath, userPolicyErr := l.LoadUserPolicy(l.Username, true)
	if userPolicyErr != nil {
		if l.LoadWithScript {
			userPolicyFilePath := path.Join("/home", l.Username, ".opk", "auth_id")
			// it is possible this the policy is in the user's home directory we need use to a script with sudoer access to read it
			// TODO: This isn't a good place for this code. The file loaders need to be rearchitected
			cmd := exec.Command("bash", "/usr/local/bin/opkssh_read_home.sh", l.Username)
			log.Println("running sudoer script to read auth_id in user's home directory, command: ", cmd)
			output, err := cmd.CombinedOutput()
			if err != nil {
				log.Printf("error loading policy using command %v got err %v", cmd, err)
			} else {
				userPolicy = FromTable(output, userPolicyFilePath)
			}
		} else {
			log.Println("warning: failed to load user policy:", userPolicyErr)
		}
	}
	// Log warning if no error loading, but userPolicy is empty meaning that
	// there are no valid entries
	if userPolicyErr == nil && len(userPolicy.Users) == 0 {
		log.Printf("warning: user policy %s has no valid user entries; an entry is considered valid if it gives %s access.", userPolicyFilePath, l.Username)
	}

	// Failed to read both policies. Return multi-error
	if rootPolicy == nil && userPolicy == nil {
		return nil, EmptySource{}, errors.Join(rootPolicyErr, userPolicyErr)
	}

	// TODO-Yuval: Optimize by merging duplicate entries instead of blindly
	// appending
	readPaths := []string{}
	if rootPolicy != nil {
		policy.Users = append(policy.Users, rootPolicy.Users...)
		readPaths = append(readPaths, SystemDefaultPolicyPath)
	}
	if userPolicy != nil {
		policy.Users = append(policy.Users, userPolicy.Users...)
		readPaths = append(readPaths, userPolicyFilePath)
	}

	return policy, FileSource(strings.Join(readPaths, ", ")), nil
}
