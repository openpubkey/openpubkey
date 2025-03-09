FROM golang:1.22-bookworm

# Update/Upgrade
RUN apt-get update -y && apt-get upgrade -y

# Install dependencies, such as the SSH server
RUN apt-get install -y sudo openssh-server telnet jq

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

# Create unprivileged user named "test2" 
RUN useradd -rm -d /home/test2 -s /bin/bash -u 1001 test2
# Set password to "test"
RUN  echo "test2:test" | chpasswd

# Allow SSH access
RUN mkdir /var/run/sshd

# ARG AUTH_CMD_USER="opksshuser"
ARG AUTH_CMD_GROUP="opksshgroup"
# Creates AuthorizedKeysCommand user and group
# RUN groupadd --system $AUTH_CMD_GROUP
# RUN /usr/sbin/useradd -r -M -s /sbin/nologin -g $AUTH_CMD_GROUP $AUTH_CMD_USER

# Setup OPK directories/files (root policy)
# RUN mkdir -p /etc/opk
# RUN touch /etc/opk/auth_id
# RUN chown root:${AUTH_CMD_GROUP} /etc/opk/auth_id
# RUN chmod 640 /etc/opk/auth_id
# RUN touch /etc/opk/providers
# RUN chmod 640 /etc/opk/providers
# RUN cat /etc/opk/providers
# RUN chown root:${AUTH_CMD_GROUP} /etc/opk/providers



# Comment out existing AuthorizedKeysCommand configuration
# RUN sed -i '/^AuthorizedKeysCommand /s/^/#/' /etc/ssh/sshd_config
# RUN sed -i '/^AuthorizedKeysCommandUser /s/^/#/' /etc/ssh/sshd_config






# Expose SSH server so we can ssh in from the tests
EXPOSE 22

# Set destination for COPY
WORKDIR /app

# Download Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy our repo
COPY . ./

# Build "opkssh" binary and write to the opk directory
ARG ISSUER_PORT="9998"
RUN go build -v -o opksshbuild ./opkssh
RUN chmod +x ./opkssh/scripts/install-linux.sh
RUN bash ./opkssh/scripts/install-linux.sh --install-from=opksshbuild --no-sshd-restart
# RUN chmod 700 /usr/local/bin/opkssh

# Setup OPK directories/files (unprivileged "test2" user)
RUN mkdir -p /home/test2/.opk 
RUN chown test2:test2 /home/test2/.opk
RUN chmod 700 /home/test2/.opk
# Create personal policy file in user's home directory
RUN touch /home/test2/.opk/auth_id
# TODO: After the rearch we won't need this to be in the group. Change back to just test2
RUN chown test2:opksshgroup /home/test2/.opk/auth_id
RUN chmod 640 /home/test2/.opk/auth_id

RUN echo "http://oidc.local:${ISSUER_PORT}/ web oidc_refreshed" >> /etc/opk/providers
# RUN chown root:${AUTH_CMD_GROUP} /etc/opk/providers
# RUN chmod 640 /etc/opk/providers

# Copy binary to unprivileged user's home directory
RUN cp /usr/local/bin/opkssh /home/test2/.opk/opkssh
RUN chown test2:test2 /home/test2/.opk/opkssh

# RUN touch /var/log/opkssh.log
# RUN chown root:${AUTH_CMD_GROUP} /var/log/opkssh.log
# RUN chmod 660 /var/log/opkssh.log

# Add integration test user as allowed email in policy (this directly tests
# policy "add" command)
ARG BOOTSTRAP_POLICY
RUN if [ -n "$BOOTSTRAP_POLICY" ] ; then opkssh add "test" "test-user@zitadel.ch" "http://oidc.local:${ISSUER_PORT}/"; else echo "Will not init policy" ; fi

# Add our AuthorizedKeysCommand line so that the opk verifier is called when
# ssh-ing in
# RUN echo "AuthorizedKeysCommand /usr/local/bin/opkssh verify %u %k %t\nAuthorizedKeysCommandUser ${AUTH_CMD_USER}" >> /etc/ssh/sshd_config
# TODO: Use the unprivileged user for the AuthorizedKeysCommandUser
RUN echo "AuthorizedKeysCommand /usr/local/bin/opkssh verify %u %k %t\nAuthorizedKeysCommandUser root" >> /etc/ssh/sshd_config

# Start SSH server on container startup
CMD ["/usr/sbin/sshd", "-D"]