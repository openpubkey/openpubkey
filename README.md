# freessh
OpenPubKey SSH
![freessh](https://github.com/bastionzero/freessh/assets/10800317/88409a18-acce-475f-99fd-f3224a7deef1)
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
scp freessh ${HOSTNAME}:~
```
3. SSH onto the server 
```bash
ssh ${HOSTNAME}
```
4. Create our file directory on the server and move the executable there:
```bash
sudo mkdir /etc/opk
sudo mv ~/freessh /etc/opk
sudo chown root /etc/opk/freessh
sudo chmod 700 /etc/opk/freessh 
```
4. Create our policy on the server
```bash
sudo touch /etc/opk/policy
sudo echo "${YOUR_EMAIL} ec2-user" > /etc/opk/policy
sudo chown root /etc/opk/policy
sudo chmod 600 /etc/opk/policy
```

## Connecting via the Client
1. Build the client cli from the root of the freessh repo:
```bash
go build
```
2. Login
```bash
./freessh login
```
3. Get the IP of the server, (this is a neat trick for our AL2 bzero linux instances):
```bash
ssh lucie-linux-agent "curl -s http://169.254.169.254/latest/meta-data/public-ipv4" 
```
4. SSH to server
```bash
ssh ${IP_ADDRESS}
```
