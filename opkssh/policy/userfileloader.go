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
	"fmt"
	"io/fs"
	"log"
	"os/exec"
	"os/user"
	"path"

	"github.com/spf13/afero"
	"golang.org/x/exp/slices"
)

// SystemDefaultPolicyPath is the default filepath where opkssh policy is
// defined
const SystemDefaultPolicyPath = "/etc/opk/auth_id"

// UserLookup defines the minimal interface to lookup users on the current
// system
type UserLookup interface {
	Lookup(username string) (*user.User, error)
}

// OsUserLookup implements the UserLookup interface by invoking the os/user
// library
type OsUserLookup struct{}

func NewOsUserLookup() UserLookup {
	return &OsUserLookup{}
}
func (OsUserLookup) Lookup(username string) (*user.User, error) { return user.Lookup(username) }

// UserPolicyLoader contains methods to read/write the opkssh policy file from/to an
// arbitrary filesystem. All methods that read policy from the filesystem fail
// and return an error immediately if the permission bits are invalid.
type UserPolicyLoader struct {
	FileLoader FileLoader
	UserLookup UserLookup
}

// NewHomePolicyLoader returns an opkssh policy loader that uses the os library to
// read/write policy from/to the user's home directory, e.g. `~/.opk/auth_id`,
func NewHomePolicyLoader() *HomePolicyLoader {
	return &HomePolicyLoader{
		UserPolicyLoader: &UserPolicyLoader{
			FileLoader: FileLoader{
				Fs:           afero.NewOsFs(),
				RequiredPerm: ModeHomePolicy,
			},
			UserLookup: NewOsUserLookup(),
		},
	}
}

// NewSystemPolicyLoader returns an opkssh policy loader that uses the os library to
// read/write system policy from/to the filesystem.
func NewSystemPolicyLoader() *SystemPolicyLoader {
	return &SystemPolicyLoader{
		UserPolicyLoader: &UserPolicyLoader{
			FileLoader: FileLoader{
				Fs:           afero.NewOsFs(),
				RequiredPerm: ModeSystemPolicy,
			},
			UserLookup: NewOsUserLookup(),
		},
	}
}

func (l UserPolicyLoader) CreateIfDoesNotExist(path string) error {
	return l.FileLoader.CreateIfDoesNotExist(path)
}

// LoadPolicyAtPath validates that the policy file at path exists, can be read
// by the current process, and has the correct permission bits set. Parses the
// contents and returns a policy.Policy if file permissions are valid and
// reading is successful; otherwise returns an error.
func (l *UserPolicyLoader) LoadPolicyAtPath(path string) (*Policy, error) {
	content, err := l.FileLoader.LoadFileAtPath(path)
	if err != nil {
		return nil, err
	}

	policy := FromTable(content, path)
	return policy, nil
}

// Dump encodes the policy into file and writes the contents to the filepath
// path
func (l *UserPolicyLoader) Dump(policy *Policy, path string) error {
	fileBytes, err := policy.ToTable()
	if err != nil {
		return err
	}

	// Write to disk
	if err := l.FileLoader.Dump(fileBytes, path); err != nil {
		return fmt.Errorf("failed to write to policy file %s: %w", path, err)
	}

	return nil
}

// SystemPolicyLoader contains methods to read/write the opkssh policy file from/to an
// arbitrary filesystem. All methods that read policy from the filesystem fail
// and return an error immediately if the permission bits are invalid.
type SystemPolicyLoader struct {
	*UserPolicyLoader
}

// LoadSystemPolicy reads the opkssh policy at SystemDefaultPolicyPath.
// An error is returned if the file cannot be read or if the permissions bits
// are not correct.
func (s *SystemPolicyLoader) LoadSystemPolicy() (*Policy, Source, error) {
	policy, err := s.LoadPolicyAtPath(SystemDefaultPolicyPath)
	if err != nil {
		return nil, EmptySource{}, fmt.Errorf("failed to read system default policy file %s: %w", SystemDefaultPolicyPath, err)
	}
	return policy, FileSource(SystemDefaultPolicyPath), nil
}

// HomePolicyLoader contains methods to read/write the opkssh policy file from/to an
// arbitrary filesystem. All methods that read policy from the filesystem fail
// and return an error immediately if the permission bits are invalid.
type HomePolicyLoader struct {
	*UserPolicyLoader
}

// LoadHomePolicy reads the user's opkssh policy at ~/.opk/auth_id (where ~
// maps to username's home directory) and returns the filepath read. An error is
// returned if the file cannot be read, if the permission bits are not correct,
// or if there is no user with username or has no home directory.
//
// If skipInvalidEntries is true, then invalid user entries are skipped and not
// included in the returned policy. A user policy's entry is considered valid if
// it gives username access. The returned policy is stripped of invalid entries.
func (h *HomePolicyLoader) LoadHomePolicy(username string, readUsingScript bool, skipInvalidEntries bool) (*Policy, string, error) {
	// TODO: Replace readUsingScript with a optional function that can run the script

	policyFilePath, err := h.UserPolicyPath(username)
	if err != nil {
		return nil, "", fmt.Errorf("error getting user policy path for user %s: %w", username, err)
	}

	policyBytes, userPolicyErr := h.FileLoader.LoadFileAtPath(policyFilePath)
	if userPolicyErr != nil {
		if readUsingScript {
			// Ensure the script has the correct permissions and ownership
			scriptPath := "/usr/local/bin/opkssh_read_home.sh"
			scriptInfo, err := h.FileLoader.Fs.Stat(scriptPath)
			if err != nil {
				return nil, "", fmt.Errorf("failed to describe the expected script at path: %w", err)
			}
			mode := scriptInfo.Mode()
			// If a non-root user can write to the script, then we have enabled minor privilege escalation
			onlyOwnerCanWrite := fs.FileMode(0755)
			if mode.Perm() != fs.FileMode(0755) {
				return nil, "", fmt.Errorf("script has unsafe file permissions expected (%o), got (%o)", onlyOwnerCanWrite, mode.Perm())
			}

			// it is possible this the policy is in the user's home directory we need use to a script with sudoer access to read it
			cmd := exec.Command("bash", scriptPath, username)
			log.Println("running sudoer script to read auth_id in user's home directory, command: ", cmd)
			output, err := cmd.CombinedOutput()
			if err != nil {
				return nil, "", fmt.Errorf("error loading policy using command %v got output %v and err %v, ", cmd, string(output), err)
			} else {
				policyBytes = output
			}
		} else {
			return nil, "", fmt.Errorf("failed to read user policy file %s: %w", policyFilePath, err)
		}
	}
	policy := FromTable(policyBytes, policyFilePath)

	if skipInvalidEntries {
		// Build valid user policy. Ignore user entries that give access to a
		// principal not equal to the username where the policy file was read
		// from.
		validUserPolicy := new(Policy)
		for _, user := range policy.Users {
			if slices.Contains(user.Principals, username) {
				// Build clean entry that only gives access to username
				validUserPolicy.Users = append(validUserPolicy.Users, User{
					EmailOrSub: user.EmailOrSub,
					Principals: []string{username},
					Issuer:     user.Issuer,
				})
			}
		}
		return validUserPolicy, policyFilePath, nil
	} else {
		// Just return what we read
		return policy, policyFilePath, nil
	}
}

// UserPolicyPath returns the path to the user's opkssh policy file at
// ~/.opk/auth_id.
func (h *HomePolicyLoader) UserPolicyPath(username string) (string, error) {
	user, err := h.UserLookup.Lookup(username)
	if err != nil {
		return "", fmt.Errorf("failed to lookup username %s: %w", username, err)
	}
	userHomeDirectory := user.HomeDir
	if userHomeDirectory == "" {
		return "", fmt.Errorf("user %s does not have a home directory", username)
	}

	policyFilePath := path.Join(userHomeDirectory, ".opk", "auth_id")
	return policyFilePath, nil
}
