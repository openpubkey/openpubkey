
# Installing opkssh

This document provides a detailed description of how our [install-linux.sh](https://raw.githubusercontent.com/openpubkey/openpubkey/main/opkssh/scripts/install-linux.sh) script works and the security protections used.

If you just want to install opkssh you should run:

```bash
wget -qO- "https://raw.githubusercontent.com/openpubkey/openpubkey/main/opkssh/scripts/install-linux.sh" | sudo bash
```

## Script commands

Running `./install-linux.sh --help` will show you all available flags.

`--nosshd-restart` turns off the sshd restart. This is useful in some docker setups where restarting sshd can break docker.

`--install-from=FILEPATH` allows you to install the opkssh binary from a local file.
This is useful if you want to install a locally built opkssh binary.

`--install-version=VER` downloads and installs a particular release of opkssh. By default we download and install the latest release of opkssh.

## What the script is doing

**1: Build opkssh.** Run the following from the root directory, replace GOARCH and GOOS to match with server you wish to install OPKSSH. This will generate the opkssh binary.

```bash
go build ./opkssh
```

**2: Copy opkssh to server.** Copy the opkssh binary you just built in the previous step to the SSH server you want to configure

```bash
scp opkssh ${USER}@${HOSTNAME}:~
```

**3: Install opkssh on server.** SSH to the server

Create the following file directory structure on the server and move the executable there:

```bash
sudo mkdir /etc/opk
sudo sudo mv ~/opkssh /usr/local/bin/opkssh
sudo chown root /usr/local/bin/opkssh
sudo chmod 755 /usr/local/bin/opkssh
```

**3: Setup policy.**

The file `/etc/opk/providers` configures what the allowed OpenID Connect providers are.

The default values for `/etc/opk/providers` are:

```bash
# Issuer Client-ID expiration-policy 
https://accounts.google.com 411517154569-7f10v0ftgp5elms1q8fm7avtp33t7i7n.apps.googleusercontent.com 24h
https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0 096ce0a3-5e72-4da8-9c86-12924b294a01 24h
```

`/etc/opk/providers` requires the following permissions (by default we create all configuration files with the correct permissions):

```bash
sudo chown root:opksshgroup /etc/opk/providers
sudo chmod 640 /etc/opk/providers
```

The file `/etc/opk/auth_id` controls which users and user identities can access the server using opkssh.
If you do not have root access, you can create a new auth_id file in at ~/auth_id and use that instead.

```bash
sudo touch /etc/opk/auth_id
sudo chown root:opksshgroup /etc/opk/auth_id
sudo chmod 640 /etc/opk/auth_id
sudo opkssh add {USER} {EMAIL} {ISSUER}
```

**4: Configure sshd to use opkssh.** Add the following lines to the sshd configuration file `/etc/ssh/sshd_config`.

```bash
AuthorizedKeysCommand /usr/local/bin/opkssh verify %u %k %t
AuthorizedKeysCommandUser opksshuser
```

Then create the required AuthorizedKeysCommandUser and group

```bash
sudo groupadd --system opksshgroup
sudo useradd -r -M -s /sbin/nologin -g opksshgroup opksshuser
```

**5: Restart sshd.**

```bash
sudo systemctl restart sshd
```

**6: Create suoders script.**

If you want to enable users to configure what OIDC identities can connect to their linux account.
You must create the following script in `/usr/local/bin/opkssh_read_home.sh`

```bash
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
```

```bash
sudo chown root /usr/local/bin/opkssh_read_home.sh
sudo chmod 755 /usr/local/bin/opkssh_read_home.sh
sudo chmod +x /usr/local/bin/opkssh_read_home.sh
```

Then added the following lines to your sudoers file at `/etc/sudoers`

```bash
opksshuser ALL=(ALL) NOPASSWD: /bin/cat /home/*/.opk/auth_id
opksshuser ALL=(ALL) NOPASSWD: /bin/stat *
```
