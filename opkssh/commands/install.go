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

package commands

import (
	"fmt"
	"os"
	"os/exec"
)

// Install setups opkssh on a server
func Install() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root or sudo")
	}

	opksshExePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %v", err)
	}

	installScript := `
#!/bin/sh

PROVIDER_GOOGLE="https://accounts.google.com 992028499768-ce9juclb3vvckh23r83fjkmvf1lvjq18.apps.googleusercontent.com 24h"
PROVIDER_MICROSOFT="https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0 bd345b9c-6902-400d-9e18-45abdf0f698f 24h"

sudo mkdir -p /etc/opk
sudo touch /etc/opk/auth_id
sudo chown root /etc/opk/auth_id
sudo chmod 600 /etc/opk/auth_id

sudo touch /etc/opk/providers
sudo chown root /etc/opk/providers
sudo chmod 600 /etc/opk/providers

if [ -s /etc/opk/providers ]; then
	echo "The providers policy file (/etc/opk/providers) is not empty. Keeping existing values"
else
	echo "$PROVIDER_GOOGLE" >> /etc/opk/providers
	echo "$PROVIDER_MICROSOFT" >> /etc/opk/providers
fi

sed -i '/^AuthorizedKeysCommand /s/^/#/' /etc/ssh/sshd_config
sed -i '/^AuthorizedKeysCommandUser /s/^/#/' /etc/ssh/sshd_config
echo "AuthorizedKeysCommand /etc/opk/opkssh verify %u %k %t\nAuthorizedKeysCommandUser root" >> /etc/ssh/sshd_config
sudo systemctl restart ssh

`
	installScript += fmt.Sprintf("sudo cp %s /etc/opk/opkssh\n", opksshExePath)

	cmd := exec.Command("sh", "-c", installScript)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to run script: %v", err)
	}

	return nil
}
