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

PROVIDER_GOOGLE="https://accounts.google.com 411517154569-7f10v0ftgp5elms1q8fm7avtp33t7i7n.apps.googleusercontent.com 24h"
PROVIDER_MICROSOFT="https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0 096ce0a3-5e72-4da8-9c86-12924b294a01 24h"
PROVIDER_GITLAB="https://gitlab.com 8d8b7024572c7fd501f64374dec6bba37096783dfcd792b3988104be08cb6923 24h"

AUTH_CMD_USER="opksshuser"
AUTH_CMD_GROUP="opksshgroup"

/usr/bin/getent group $AUTH_CMD_GROUP || groupadd --system $AUTH_CMD_GROUP
echo "Created group: $AUTH_CMD_USER"

# If the AuthorizedKeysCommand user does not exist, create it and add it to the group
if ! getent passwd "$AUTH_CMD_USER" >/dev/null; then
    sudo useradd -r -M -s /sbin/nologin -g "$AUTH_CMD_GROUP" "$AUTH_CMD_USER"
    echo "Created user: $AUTH_CMD_USER and added to group: $AUTH_CMD_GROUP"
else
    # If the AuthorizedKeysCommand user exist, ensure it is added to the group
    sudo usermod -aG "$AUTH_CMD_GROUP" "$AUTH_CMD_USER"
    echo "Added $AUTH_CMD_USER to group: $AUTH_CMD_GROUP"
fi

sudo mkdir -p /etc/opk
sudo touch /etc/opk/auth_id
sudo chown root:${AUTH_CMD_GROUP} /etc/opk/auth_id
sudo chmod 640 /etc/opk/auth_id

sudo touch /etc/opk/providers
sudo hown root:${AUTH_CMD_GROUP} /etc/opk/providers
sudo chmod 640 /etc/opk/providers

if [ -s /etc/opk/providers ]; then
	echo "The providers policy file (/etc/opk/providers) is not empty. Keeping existing values"
else
	echo "$PROVIDER_GOOGLE" >> /etc/opk/providers
	echo "$PROVIDER_MICROSOFT" >> /etc/opk/providers
	echo "$PROVIDER_GITLAB" >> /etc/opk/providers
fi

sed -i '/^AuthorizedKeysCommand /s/^/#/' /etc/ssh/sshd_config
sed -i '/^AuthorizedKeysCommandUser /s/^/#/' /etc/ssh/sshd_config
echo "AuthorizedKeysCommand /usr/local/bin/opkssh verify %u %k %t\nAuthorizedKeysCommandUser root" >> /etc/ssh/sshd_config
sudo systemctl restart ssh

`
	installScript += fmt.Sprintf("sudo cp %s /usr/local/bin/opkssh\n", opksshExePath)

	cmd := exec.Command("sh", "-c", installScript)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to run script: %v", err)
	}

	return nil
}
