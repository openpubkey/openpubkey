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

// NewUserFileLoader returns an opkssh policy loader that uses the os library to
// read/write policy from/to the filesystem.
func NewUserFileLoader() *UserPolicyLoader {
	return &UserPolicyLoader{
		FileLoader: FileLoader{
			Fs: afero.NewOsFs(),
		},
		UserLookup: NewOsUserLookup(),
	}
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

	policy, err := FromTable(content, path)
	if err != nil {
		return nil, err
	}

	return policy, nil
}

// LoadSystemDefaultPolicy reads the opkssh policy at SystemDefaultPolicyPath.
// An error is returned if the file cannot be read or if the permissions bits
// are not correct.
func (l *UserPolicyLoader) LoadSystemDefaultPolicy() (*Policy, error) {
	policy, err := l.LoadPolicyAtPath(SystemDefaultPolicyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read system default policy file %s: %w", SystemDefaultPolicyPath, err)
	}

	return policy, nil
}

// LoadUserPolicy reads the user's opkssh policy at ~/.opk/auth_id (where ~
// maps to username's home directory) and returns the filepath read. An error is
// returned if the file cannot be read, if the permission bits are not correct,
// or if there is no user with username or has no home directory.
//
// If skipInvalidEntries is true, then invalid user entries are skipped and not
// included in the returned policy. A user policy's entry is considered valid if
// it gives username access. The returned policy is stripped of invalid entries.
func (l *UserPolicyLoader) LoadUserPolicy(username string, skipInvalidEntries bool) (*Policy, string, error) {
	user, err := l.UserLookup.Lookup(username)
	if err != nil {
		return nil, "", fmt.Errorf("failed to lookup username %s: %w", username, err)
	}
	userHomeDirectory := user.HomeDir
	if userHomeDirectory == "" {
		return nil, "", fmt.Errorf("user %s does not have a home directory", username)
	}

	policyFilePath := path.Join(userHomeDirectory, ".opk", "auth_id")
	policy, err := l.LoadPolicyAtPath(policyFilePath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read user policy file %s: %w", policyFilePath, err)
	}

	if skipInvalidEntries {
		// Build valid user policy. Ignore user entries that give access to a
		// principal not equal to the username where the policy file was read
		// from.
		validUserPolicy := new(Policy)
		for _, user := range policy.Users {
			if slices.Contains(user.Principals, username) {
				// Build clean entry that only gives access to username
				validUserPolicy.Users = append(validUserPolicy.Users, User{
					Email:      user.Email,
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
