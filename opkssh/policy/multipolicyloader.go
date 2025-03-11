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
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/openpubkey/openpubkey/opkssh/policy/files"
)

var _ Loader = &MultiPolicyLoader{}

// FileSource implements policy.Source by returning a string that is expected to
// be a filepath
type FileSource string

func (s FileSource) Source() string {
	return string(s)
}

// MultiPolicyLoader implements policy.Loader by reading both the system default
// policy (root policy) and user policy (~/.opk/auth_id where ~ maps to
// Username's home directory)
type MultiPolicyLoader struct {
	HomePolicyLoader   *HomePolicyLoader
	SystemPolicyLoader *SystemPolicyLoader
	LoadWithScript     bool
	Username           string
}

func (l *MultiPolicyLoader) Load() (*Policy, Source, error) {
	policy := new(Policy)

	// Try to load the root policy
	rootPolicy, _, rootPolicyErr := l.SystemPolicyLoader.LoadSystemPolicy()
	if rootPolicyErr != nil {
		log.Println("warning: failed to load system default policy:", rootPolicyErr)
	}
	// Try to load the user policy
	userPolicy, userPolicyFilePath, userPolicyErr := l.HomePolicyLoader.LoadHomePolicy(l.Username, true, ReadWithSudoScript)
	if userPolicyErr != nil {
		log.Println("warning: failed to load user policy:", userPolicyErr)
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

// ReadWithSudoScript specifies additional way of loading the policy in the
// user's home directory (`~/.opk/auth_id`). This is needed when the
// AuthorizedKeysCommand user does not have privileges to transverse the user's
// home directory. Instead we use a script and special sudoers permissions scoped
// specifically to read the policy file.
func ReadWithSudoScript(h *HomePolicyLoader, username string) ([]byte, error) {
	path := "/home/" + username + "/.opk/auth_id"

	statCmd := exec.Command("sudo", "-n", "/bin/stat", "-c", "%a", path)
	statPerms, err := statCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("error loading policy using command %v got output %v and err %v", statCmd, string(statPerms), err)
	}
	expectedPerms := fmt.Sprintf("%o", files.ModeHomePerms.Perm())
	if expectedPerms != strings.TrimSpace(string(statPerms)) {
		return nil, fmt.Errorf("policy file %s has insecure permissions: %s", path, statPerms)
	}

	statCmd = exec.Command("sudo", "-n", "/bin/stat", "-c", "%U", path)
	statOwner, err := statCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("error loading policy using command %v got output %v and err %v", statCmd, string(statOwner), err)
	}
	if username != strings.TrimSpace(string(statOwner)) {
		return nil, fmt.Errorf("policy file %s has insecure permissions: %s", path, statPerms)
	}

	// Security critical: We reading this file as `sudo -u opksshuser`
	// and opksshuser has elevated permissions to read any file whose
	// path matches `/home/*/opk/auth_id`. We need to be cautious we do follow
	// a symlink as it could be to a file the user is not permitted to read.
	// This would not permit the user to read the file, but they might be able
	// to determine the existence of the file.
	statCmd = exec.Command("sudo", "-n", "/bin/stat", "-c", "%F", path)
	statSymlink, err := statCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("error loading policy using command %v got output %v and err %v", statCmd, string(statSymlink), err)
	}
	if strings.TrimSpace(string(statSymlink)) != "regular file" {
		return nil, fmt.Errorf("refusing to load unsafe policy file %s (file is a symlink): %s", path, statSymlink)
	}

	catCmd := exec.Command("sudo", "-n", "/bin/cat", path)
	catOutput, err := catCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("error loading policy using command %v got output %v and err %v", catCmd, string(catOutput), err)
	}

	return catOutput, nil
}
