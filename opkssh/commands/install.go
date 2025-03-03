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

# Creates script that can read ~/.opk/auth_id
OUTPUT_SCRIPT="/etc/opk/check_home.sh"
cat << 'EOF' > $OUTPUT_SCRIPT
#!/bin/bash

# ensure script fails on any error
set -euo pipefail

# Ensure exactly one argument is passed (user)
if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <user>" >&2
    exit 1
fi

USER=$1
AUTH_FILE="/home/$USER/.opk/auth_id"

if ! sudo /bin/cat "$AUTH_FILE" > /dev/null; then
    echo "Error: $AUTH_FILE does not exist or insufficient permissions" >&2
    exit 1
fi

# Check if the file permissions are 600
PERMISSIONS=$(sudo -n /bin/stat -c "%a" "$AUTH_FILE")
if [[ "$PERMISSIONS" -ne 600 ]]; then
    echo "Error: $AUTH_FILE permissions are not 600" >&2
    exit 1
fi

# Check if the file is owned by the user
OWNER=$(sudo -n /bin/stat -c "%U" "$AUTH_FILE")
if [[ "$OWNER" != "$USER" ]]; then
    echo "Error: $AUTH_FILE is not owned by $USER" >&2
    exit 1
fi


if ! sudo -n /bin/cat "$AUTH_FILE"; then
    echo "Error: Unable to access $AUTH_FILE" >&2
    exit 1
fi

EOF
chmod +x $OUTPUT_SCRIPT

SUDOERS_RULE_CAT="$AUTH_CMD_USER ALL=(ALL) NOPASSWD: /bin/cat /home/*/.opk/auth_id"
if ! sudo grep -qxF "$SUDOERS_RULE_CAT" /etc/sudoers; then
    echo "Adding sudoers rule for $AUTH_CMD_USER..."
    echo "$SUDOERS_RULE_CAT" | sudo tee -a /etc/sudoers > /dev/null
fi

SUDOERS_RULE_STAT="$AUTH_CMD_USER ALL=(ALL) NOPASSWD: /bin/stat *"
if ! sudo grep -qxF "$SUDOERS_RULE_STAT" /etc/sudoers; then
    echo "Adding sudoers rule for $AUTH_CMD_USER..."
    echo "$SUDOERS_RULE_STAT" | sudo tee -a /etc/sudoers > /dev/null
fi

sudo mkdir -p /etc/opk
sudo touch /etc/opk/auth_id
sudo chown root:${AUTH_CMD_GROUP} /etc/opk/auth_id
sudo chmod 640 /etc/opk/auth_id

sudo touch /etc/opk/providers
sudo chown root:${AUTH_CMD_GROUP} /etc/opk/providers
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
echo "AuthorizedKeysCommand /usr/local/bin/opkssh verify %u %k %t\nAuthorizedKeysCommandUser ${AUTH_CMD_USER}" >> /etc/ssh/sshd_config
sudo systemctl restart ssh

touch /var/log/opkssh.log
chown root:${AUTH_CMD_GROUP} /var/log/opkssh.log
chmod 660 /var/log/opkssh.log
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
