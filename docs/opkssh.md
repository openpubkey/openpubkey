
// Setup on Ubuntu
// sudo apt install openssh-server
//
// sudo mkdir -p /etc/opk
// sudo touch /etc/opk/auth_id
// sudo chown root /etc/opk/auth_id
// sudo chmod 600 /etc/opk/auth_id
//
//
// cd to the source code directory openpubkey
// sudo go build -v -o /etc/opk/opkssh ./opkssh
// sudo chmod 700 /etc/opk/opkssh

//
// mkdir -p /home/e0/.opk
// chown e0:e0 /home/e0/.opk
// chmod 700 /home/e0/.opk
//
// touch /home/e0/.opk/auth_id
// chown e0:e0 /home/e0/.opk/auth_id
// chmod 600 /home/e0/.opk/auth_id
//
// ./opkssh add eth3rs@gmail.com e0 google
// 2025/02/11 15:59:14 Successfully added new policy to /home/e0/.opk/auth_id

// This should be much easier to setup. Like a helper script that does all of this for you

// // sudo issue where sudo echo does run as sudo
// echo "AuthorizedKeysCommand /etc/opk/opkssh verify %u %k %t" >> /etc/ssh/sshd_config
// echo "AuthorizedKeysCommandUser root" >> /etc/ssh/sshd_config
// sudo systemctl restart ssh