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

	"github.com/spf13/afero"
)

// ModeOnlyOwner is the expected permission bits that should be set for opkssh
// policy files. This mode means that only the owner of the file can read
// TODO: Rename this as we using groups now
const ModeOnlyOwner = fs.FileMode(0640)

// UserPolicyLoader contains methods to read/write the opkssh policy file from/to an
// arbitrary filesystem. All methods that read policy from the filesystem fail
// and return an error immediately if the permission bits are invalid.
type FileLoader struct {
	Fs afero.Fs
}

func (l FileLoader) CreateIfDoesNotExist(path string) error {
	exists, err := afero.Exists(l.Fs, path)
	if err != nil {
		return err
	}
	if !exists {
		if err := l.Fs.MkdirAll(afero.GetTempDir(l.Fs, path), 0755); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
		file, err := l.Fs.Create(path)
		if err != nil {
			return fmt.Errorf("failed to create file: %w", err)
		}
		file.Close()
		if err := l.Fs.Chmod(path, ModeOnlyOwner); err != nil {
			return fmt.Errorf("failed to set file permissions: %w", err)
		}
	}
	return nil
}

// LoadFileAtPath validates that the file at path exists, can be read
// by the current process, and has the correct permission bits set. Parses the
// contents and returns the bytes if file permissions are valid and
// reading is successful; otherwise returns an error.
func (l *FileLoader) LoadFileAtPath(path string) ([]byte, error) {
	// Get file info and check if file exists
	info, err := l.Fs.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to describe the file at path: %w", err)
	}

	// Validate that file has correct permission bits set
	err = l.validatePermissions(info)
	if err != nil {
		return nil, fmt.Errorf("policy file has insecure permissions: %w", err)
	}

	// Read file contents
	afs := &afero.Afero{Fs: l.Fs}
	content, err := afs.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return content, nil
}

func (l *FileLoader) validatePermissions(fileInfo fs.FileInfo) error {
	mode := fileInfo.Mode()

	// only the owner of this file should be able to write to it
	if mode.Perm() != ModeOnlyOwner {
		return fmt.Errorf("expected (0640), got (%o)", mode.Perm())
	}

	return nil
}

// Dump writes fileBytes to the filepath
func (l *FileLoader) Dump(fileBytes []byte, path string) error {
	// Write to disk
	if err := afero.WriteFile(l.Fs, path, fileBytes, ModeOnlyOwner); err != nil {
		return err
	}
	return nil
}
