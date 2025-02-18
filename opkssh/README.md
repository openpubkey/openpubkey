# OPKSSH

OpenPubkey SSH (OPKSSH)

For more documentation see: [PR: Adds SSH support to OpenPubkey](https://github.com/openpubkey/openpubkey/pull/43) and [PR: Azure and Google support in OPKSSH](https://github.com/openpubkey/openpubkey/pull/244)

## How to Test

Here are some instructions for using OPKSSH. The server is an server that you wish to ssh into using opkssh. You need root level privileges to install opkssh on a server.

### Setting up the Server

The directions below are for an AL2 box but can be modified for another OS.

**1: Build opkssh.** Run the following from the root directory, replace GOARCH and GOOS to match with server you wish to install OPKSSH. This will generate the opkssh binary.

```bash
GOARCH=amd64 GOOS=linux go build
```

**2: Copy opkssh to server.** Copy the opkssh binary you just built in the previous step to the SSH server you want to configure

```bash
scp opkssh ${USER}@${HOSTNAME}:~
```

**3: Install opkssh on server.** SSH to the server

```bash
ssh ${HOSTNAME}
```

Create the following file directory structure on the server and move the executable there:

```bash
sudo mkdir /etc/opk
sudo mv ~/opkssh /etc/opk
sudo chown root /etc/opk/opkssh
sudo chmod 700 /etc/opk/opkssh 
```

**3: Setup policy.** The file `/etc/opk/auth_id` controls which users and user identities can access the server using opkssh. If you do not have root access,
create a new auth_id file in at ~/auth_id and use that instead. You
will also need to have a opkssh binary available to use in the same directory.

```bash
sudo touch /etc/opk/auth_id
sudo chown root /etc/opk/auth_id
sudo chmod 600 /etc/opk/auth_id
sudo /etc/opk/opkssh add {USER} {EMAIL} {ISSUER}
```

**4: Configure sshd to use opkssh.** Add the following lines to the sshd configuration file `/etc/ssh/sshd_config`.

```bash
AuthorizedKeysCommand /etc/opk/opkssh verify %u %k %t
AuthorizedKeysCommandUser root
```

**5: Restart sshd.**

```bash
sudo systemctl restart sshd
```

## Connecting via the Client

You need to first make sure you have `opkssh`. You can build it locally in from the  `opkssh` directory in the `openpubkey` repo using `go build`.

1. Run `./opkssh login` this will open a browser window to authenticate to your OpenID Provider. After authenticating opkssh will generate an ssh key in your default `.ssh` directory.
2. Then ssh to the server as you would normally `ssh alice@$ssh-server`
