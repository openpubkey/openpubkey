# opkssh
OpenPubKey SSH

For more documentation see: https://github.com/openpubkey/openpubkey/pull/43

# How to Test
## Setting up the Server
The directions below are for an AL2 box but can be modified for another OS.

1. Build our verifier. Run the following from the root directory, replace GOARCH and GOOS to match with server:
```bash
GOARCH=amd64 GOOS=linux go build
```
2. Copy the built binary up to the SSH server you want to configure
```bash
scp opkssh ${USER}@${HOSTNAME}:~
```
3. SSH onto the server 
```bash
ssh ${HOSTNAME}
```
4. Create our file directory on the server and move the executable there:
```bash
sudo mkdir /etc/opk
sudo mv ~/opkssh /etc/opk
sudo chown root /etc/opk/opkssh
sudo chmod 700 /etc/opk/opkssh 
```
5. Create our policy on the server at /etc/opk/policy.yml. If you do not have root access,
create a new policy.yml file in at ~/policy.yml and use that instead. You
will also need to have a opkssh binary available to use in the same directory.
```bash
sudo touch /etc/opk/policy.yml
sudo chown root /etc/opk/policy.yml
sudo chmod 600 /etc/opk/policy.yml
sudo /etc/opk/opkssh add {EMAIL} {USER}
```
6. Add the folowing lines to the sshd file `/etc/ssh/sshd_config`
```bash
AuthorizedKeysCommand /etc/opk/opkssh verify %u %k %t
AuthorizedKeysCommandUser root
```
7. Restart sshd
```bash
sudo systemctl restart sshd
```

## Connecting via the Client
1. Build the client cli from the root of the opkssh repo:
```bash
go build
```
2. Login
```bash
./opkssh login
```
3. Get the IP of the server, (this is a neat trick for our AL2 bzero linux instances):
```bash
ssh lucie-linux-agent "curl -s http://169.254.169.254/latest/meta-data/public-ipv4" 
```
4. SSH to server
```bash
ssh ${USER}@${IP_ADDRESS}
```
