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
	"io/fs"
	"log"
	"os/exec"
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
	HomePolicyLoader   *HomePolicyLoader
	SystemPolicyLoader *SystemPolicyLoader
	LoadWithScript     bool
	Username           string
}

func (l *UserMultiFileLoader) Load() (*Policy, Source, error) {
	policy := new(Policy)

	// Try to load the root policy
	// TODO: Actually use the source rather _
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
	// Ensure the script has the correct permissions and ownership
	scriptPath := "/usr/local/bin/opkssh_read_home.sh"
	scriptInfo, err := h.FileLoader.Fs.Stat(scriptPath)
	if err != nil {
		return nil, fmt.Errorf("failed to describe the expected script at path: %w", err)
	}
	mode := scriptInfo.Mode()
	// Security critical: Only a root user should have permissions to write to the script as the
	// script if called with sudo -u opksshuser and opksshuser has elevated permissions.
	onlyOwnerCanWrite := fs.FileMode(0755)
	if mode.Perm() != fs.FileMode(0755) {
		return nil, fmt.Errorf("script has unsafe file permissions expected (%o), got (%o)", onlyOwnerCanWrite, mode.Perm())
	}

	// it is possible this the policy is in the user's home directory we need use to a script with sudoer access to read it
	cmd := exec.Command("bash", scriptPath, username)
	log.Println("running sudoer script to read auth_id in user's home directory, command: ", cmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("error loading policy using command %v got output %v and err %v, ", cmd, string(output), err)
	} else {
		return output, nil
	}
}
