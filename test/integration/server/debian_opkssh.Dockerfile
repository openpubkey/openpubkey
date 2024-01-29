FROM golang:1.20.12-bookworm

# Update/Upgrade
RUN apt-get update -y && apt-get upgrade -y

# Install dependencies, such as the SSH server
RUN apt-get install -y sudo openssh-server telnet

# Source:
# https://medium.com/@ratnesh4209211786/simplified-ssh-server-setup-within-a-docker-container-77eedd87a320
#
# Create an SSH user named "test". Make it a sudoer
RUN useradd -rm -d /home/test -s /bin/bash -g root -G sudo -u 1000 test
# Set password to "test"
RUN  echo "test:test" | chpasswd

# Make it so "test" user does not need to present password when using sudo
# Source: https://askubuntu.com/a/878705
RUN echo "test ALL=(ALL:ALL) NOPASSWD: ALL" | tee /etc/sudoers.d/test

# Allow SSH access
RUN mkdir /var/run/sshd

# Setup OPK directories/files
RUN mkdir -p /etc/opk
RUN touch /etc/opk/policy.yml
RUN chown root /etc/opk/policy.yml
RUN chmod 600 /etc/opk/policy.yml

# Comment out existing AuthorizedKeysCommand configuration
RUN sed -i '/^AuthorizedKeysCommand /s/^/#/' /etc/ssh/sshd_config
RUN sed -i '/^AuthorizedKeysCommandUser /s/^/#/' /etc/ssh/sshd_config

# Add our AuthorizedKeysCommand line so that the opk verifier is called when
# ssh-ing in
RUN echo "AuthorizedKeysCommand /etc/opk/opk-ssh verify %u %k %t\nAuthorizedKeysCommandUser root" >> /etc/ssh/sshd_config

# Expose SSH server so we can ssh in from the tests
EXPOSE 22

# Set destination for COPY
WORKDIR /app

# Download Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy our repo
COPY . ./

# Build "opk-ssh" binary and write to the opk directory
ARG ISSUER_PORT="9998"
# Configure the OpenIdProvider (GoogleOp) verifier code to use expected clientId
# (web), clientSecret (secret), and issuer URL (http://oidc.local:9998/). Host
# "oidc.local" should be mapped to the IP of the docker container running the
# zitadel dynamic exampleop server (configure ExtraHosts when running this
# container).
RUN go build -v -o /etc/opk/opk-ssh -ldflags "-X main.issuer=http://oidc.local:${ISSUER_PORT}/ -X main.clientID=web -X main.clientSecret=secret"
RUN chmod 700 /etc/opk/opk-ssh

# Add integration test user as allowed email in policy (this directly tests
# policy "add" command)
RUN /etc/opk/opk-ssh add "test-user@zitadel.ch" "test"

# Start SSH server on container startup
CMD ["/usr/sbin/sshd", "-D"]