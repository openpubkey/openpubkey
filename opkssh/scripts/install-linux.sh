#!/bin/bash

set -e  # Exit if any command fails

# This script generated by chatGPT4o and then modified by hand

# Define variables
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="opkssh"
GITHUB_REPO="openpubkey/openpubkey"

# Define the default OpenID Providers
PROVIDER_GOOGLE="https://accounts.google.com 411517154569-7f10v0ftgp5elms1q8fm7avtp33t7i7n.apps.googleusercontent.com 24h"
PROVIDER_MICROSOFT="https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0 096ce0a3-5e72-4da8-9c86-12924b294a01 24h"
PROVIDER_GITLAB="https://gitlab.com 8d8b7024572c7fd501f64374dec6bba37096783dfcd792b3988104be08cb6923 24h"

# AuthorizedKeysCommand user
AUTH_CMD_USER="opksshuser"
AUTH_CMD_GROUP="opksshuser"

RESTART_SSH=true
LOCAL_INSTALL_FILE=""
INSTALL_VERSION="latest"
for arg in "$@"; do
    if [ "$arg" == "--no-sshd-restart" ]; then
        RESTART_SSH=false
    elif [[ "$arg" == --install-from=* ]]; then
        LOCAL_INSTALL_FILE="${arg#*=}"
    elif [[ "$arg" == --install-version=* ]]; then
        INSTALL_VERSION="${arg#*=}"
    fi
done

# Display help message
if [[ "$1" == "--help" ]]; then
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --no-sshd-restart       Do not restart SSH after installation"
    echo "  --install-from=FILEPATH Install using a local file"
    echo "  --install-version=VER   Install a specific version from GitHub"
    echo "  --help                  Display this help message"
    exit 0
fi



# Ensure wget is installed
if ! command -v wget &> /dev/null; then
    echo "Error: wget is not installed. Please install it first."
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed. Please install it first."
    exit 1
fi


# Checks if the group and user used by the AuthorizedKeysCommand exists if not creates it
/usr/bin/getent group $AUTH_CMD_GROUP || groupadd --system $AUTH_CMD_GROUP
echo "Created group: $AUTH_CMD_USER"

# If the AuthorizedKeysCommand user does not exist, create it and add it to the group
if ! getent passwd "$AUTH_CMD_USER" >/dev/null; then
    sudo useradd -r -M -s /sbin/nologin -g "$AUTH_CMD_GROUP" "$AUTH_CMD_USER"
    echo "Created user: $AUTH_CMD_USER with group: $AUTH_CMD_GROUP"
else
    # If the AuthorizedKeysCommand user exist, ensure it is added to the group
    sudo usermod -aG "$AUTH_CMD_GROUP" "$AUTH_CMD_USER"
    echo "Added $AUTH_CMD_USER to group: $AUTH_CMD_GROUP"
fi

echo "--install-from option supplied, installing from local file: $LOCAL_INSTALL_FILE"
# Check if we should install from a local file
if [ -n "$LOCAL_INSTALL_FILE" ]; then
    BINARY_PATH=$LOCAL_INSTALL_FILE
    if [ ! -f "$BINARY_PATH" ]; then
        echo "Error: Specified binary path does not exist."
        exit 1
    fi
    echo "Using binary from specified path: $BINARY_PATH"
else
    if [ "$INSTALL_VERSION" == "latest" ]; then
        BINARY_URL="https://github.com/$GITHUB_REPO/releases/latest/download/opkssh-linux-amd64"
    else
        BINARY_URL="https://github.com/$GITHUB_REPO/releases/download/$INSTALL_VERSION/opkssh-linux-amd64"
    fi

    # Download the binary
    echo "Downloading version $INSTALL_VERSION of $BINARY_NAME from $BINARY_URL..."
    wget -q --show-progress -O "$BINARY_NAME" "$BINARY_URL"

    BINARY_PATH="$BINARY_NAME"
fi

# Move to installation directory
sudo mv "$BINARY_PATH" "$INSTALL_DIR/$BINARY_NAME"

# Make the binary executable, correct permissions/ownership
sudo chmod +x "$INSTALL_DIR/$BINARY_NAME"
sudo chown root:${AUTH_CMD_GROUP} "$INSTALL_DIR/$BINARY_NAME"
sudo chmod 711 "$INSTALL_DIR/$BINARY_NAME"

# Verify installation
if command -v $BINARY_NAME &> /dev/null; then
    # Setup configuration
    echo "Configuring opkssh."
    mkdir -p /etc/opk
    touch /etc/opk/auth_id
    chown root:${AUTH_CMD_GROUP} /etc/opk/auth_id
    chmod 640 /etc/opk/auth_id

    touch /etc/opk/providers
    chown root:${AUTH_CMD_GROUP} /etc/opk/providers
    chmod 640 /etc/opk/providers

    if [ -s /etc/opk/providers ]; then
        echo "The providers policy file (/etc/opk/providers) is not empty. Keeping existing values"
    else
        echo "$PROVIDER_GOOGLE" >> /etc/opk/providers
        echo "$PROVIDER_MICROSOFT" >> /etc/opk/providers
        echo "$PROVIDER_GITLAB" >> /etc/opk/providers
    fi

    sed -i '/^AuthorizedKeysCommand /s/^/#/' /etc/ssh/sshd_config
    sed -i '/^AuthorizedKeysCommandUser /s/^/#/' /etc/ssh/sshd_config
    echo "AuthorizedKeysCommand /usr/local/bin/opkssh verify %u %k %t" >> /etc/ssh/sshd_config
    echo "AuthorizedKeysCommandUser ${AUTH_CMD_USER}" >> /etc/ssh/sshd_config

    if [ "$RESTART_SSH" = true ]; then
        systemctl restart ssh
    else
        echo "--no-sshd-restart option supplied, skipping SSH restart."
    fi

    # Sudo regex support was added in 1.9.10. If you are using an older version of sudoer home policy will not work unless you set the AuthroizedKeysCommand user to root
    SUDOERS_RULE_READ_HOME="$AUTH_CMD_USER ALL=(ALL) NOPASSWD: /usr/local/bin/opkssh readhome *"
    if ! sudo grep -qxF "$SUDOERS_RULE_READ_HOME" /etc/sudoers; then
        echo "Adding sudoers rule for $AUTH_CMD_USER..."
        echo "$SUDOERS_RULE_READ_HOME" | sudo tee -a /etc/sudoers > /dev/null
    fi

    touch /var/log/opkssh.log
    chown root:${AUTH_CMD_GROUP} /var/log/opkssh.log
    chmod 660 /var/log/opkssh.log

    echo "Installation successful! Run '$BINARY_NAME' to use it."
else
    echo "Installation failed."
    exit 1
fi
