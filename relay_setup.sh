#!/bin/bash
relay_user='telesploit-relay'
host_name='telesploit-os'
mattermost_ver='5.8.0'
echo 'The following steps MUST be completed before running this script'
echo 'Step 1: Run the script as root'
echo 'Step 2: Open SSH, HTTP, and HTTPS to the relay (port 80 is only required by Lets Encrypt during setup)'
echo 'Step 3: An apt-get update and apt-get upgrade should be performed prior to running the script'
echo "Step 3: Validate that the FQDN for the relay resolves below"
echo
read -p 'Enter the FQDN for relay server, e.g. relay-os.telesploit.com: ' relay_fqdn
nslookup $relay_fqdn
echo
echo 'If the relay does not resolve then exit now and verify a corresponding A record exists'
read -n1 -rsp $'Press any key to continue or Ctrl+C to exit...\n'
echo
read -p 'Enter your email address for registering the Lets Encrypt certificate: ' letsencrypt_email
echo
read -s -p 'Enter the password for the mysql server (no single quotes): ' mysql_pass
echo
read -s -p 'Enter the password for the Mattermost mmuser (alphanumeric only): ' mmuser_pass
echo
echo '________________________________________________________________'
echo
echo "setting the hostname to $host_name"
hostname $host_name
echo "$host_name" > /etc/hostname
echo 'completed setting hostname'
echo
echo '________________________________________________________________'
echo
echo 'installing certbot repositories and application'
apt-get install -y software-properties-common
add-apt-repository ppa:certbot/certbot
apt-get update -y
apt-get upgrade -y
apt-get install -y certbot
# retrieving certificate
certbot certonly -d $relay_fqdn --standalone --agree-tos --no-eff-email -m $letsencrypt_email
# installing the certificate and setting permissions for use by haproxy
mkdir -p /etc/haproxy/certs
cat /etc/letsencrypt/live/$relay_fqdn/fullchain.pem /etc/letsencrypt/live/$relay_fqdn/privkey.pem > /etc/haproxy/certs/$relay_fqdn.pem
chmod -R go-rwx /etc/haproxy/certs
read -n1 -rsp $'Verify that the certificate creation and installation succeeded then press any key to continue or Ctrl+C to exit...\n'
echo 'completed certbot installation and configuration'
echo '________________________________________________________________'
echo
echo 'installing haproxy with custom configuration'
apt-get install -y haproxy
# backing up the initial haproxy configuration
mv /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.old
# creating custom haproxy configuration
echo 'global' > /etc/haproxy/haproxy.cfg
echo ' chroot /var/lib/haproxy' >> /etc/haproxy/haproxy.cfg
echo ' stats socket /run/haproxy/admin.sock mode 660 level admin' >> /etc/haproxy/haproxy.cfg
echo ' stats timeout 30s' >> /etc/haproxy/haproxy.cfg
echo ' user haproxy' >> /etc/haproxy/haproxy.cfg
echo ' group haproxy' >> /etc/haproxy/haproxy.cfg
echo ' daemon' >> /etc/haproxy/haproxy.cfg
echo >> /etc/haproxy/haproxy.cfg
echo 'maxconn 2048' >> /etc/haproxy/haproxy.cfg
echo ' tune.ssl.default-dh-param 2048' >> /etc/haproxy/haproxy.cfg
echo >> /etc/haproxy/haproxy.cfg
echo '# Default SSL material locations' >> /etc/haproxy/haproxy.cfg
echo ' ca-base /etc/ssl/certs' >> /etc/haproxy/haproxy.cfg
echo ' crt-base /etc/ssl/private' >> /etc/haproxy/haproxy.cfg
echo >> /etc/haproxy/haproxy.cfg
echo '# Default ciphers to use on SSL-enabled listening sockets.' >> /etc/haproxy/haproxy.cfg
echo ' # For more information, see ciphers(1SSL). This list is from:' >> /etc/haproxy/haproxy.cfg
echo ' # https://hynek.me/articles/hardening-your-web-servers-ssl-ciphers/' >> /etc/haproxy/haproxy.cfg
echo ' ssl-default-bind-ciphers ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+3DES:!aNULL:!MD5:!DSS' >> /etc/haproxy/haproxy.cfg
echo ' ssl-default-bind-options no-sslv3' >> /etc/haproxy/haproxy.cfg
echo >> /etc/haproxy/haproxy.cfg
echo 'defaults' >> /etc/haproxy/haproxy.cfg
echo ' log global' >> /etc/haproxy/haproxy.cfg
echo ' mode http' >> /etc/haproxy/haproxy.cfg
echo ' option httplog' >> /etc/haproxy/haproxy.cfg
echo ' option dontlognull' >> /etc/haproxy/haproxy.cfg
echo ' timeout connect 5000' >> /etc/haproxy/haproxy.cfg
echo ' timeout client 50000' >> /etc/haproxy/haproxy.cfg
echo ' timeout server 50000' >> /etc/haproxy/haproxy.cfg
echo ' errorfile 400 /etc/haproxy/errors/400.http' >> /etc/haproxy/haproxy.cfg
echo ' errorfile 403 /etc/haproxy/errors/403.http' >> /etc/haproxy/haproxy.cfg
echo ' errorfile 408 /etc/haproxy/errors/408.http' >> /etc/haproxy/haproxy.cfg
echo ' errorfile 500 /etc/haproxy/errors/500.http' >> /etc/haproxy/haproxy.cfg
echo ' errorfile 502 /etc/haproxy/errors/502.http' >> /etc/haproxy/haproxy.cfg
echo ' errorfile 503 /etc/haproxy/errors/503.http' >> /etc/haproxy/haproxy.cfg
echo ' errorfile 504 /etc/haproxy/errors/504.http' >> /etc/haproxy/haproxy.cfg
echo >> /etc/haproxy/haproxy.cfg
echo 'backend secure_http' >> /etc/haproxy/haproxy.cfg
echo ' reqadd X-Forwarded-Proto:\ https' >> /etc/haproxy/haproxy.cfg
echo ' rspadd Strict-Transport-Security:\ max-age=31536000' >> /etc/haproxy/haproxy.cfg
echo ' mode http' >> /etc/haproxy/haproxy.cfg
echo ' option httplog' >> /etc/haproxy/haproxy.cfg
echo ' option forwardfor' >> /etc/haproxy/haproxy.cfg
echo ' server local_http_server 127.0.0.1:80' >> /etc/haproxy/haproxy.cfg
echo >> /etc/haproxy/haproxy.cfg
echo 'backend ssh' >> /etc/haproxy/haproxy.cfg
echo ' mode tcp' >> /etc/haproxy/haproxy.cfg
echo ' option tcplog' >> /etc/haproxy/haproxy.cfg
echo ' server ssh 127.0.0.1:22' >> /etc/haproxy/haproxy.cfg
echo ' timeout server 2h' >> /etc/haproxy/haproxy.cfg
echo >> /etc/haproxy/haproxy.cfg
echo 'frontend ssl' >> /etc/haproxy/haproxy.cfg
echo "bind :443 ssl crt /etc/haproxy/certs/$relay_fqdn.pem no-sslv3"  >> /etc/haproxy/haproxy.cfg
echo ' mode tcp' >> /etc/haproxy/haproxy.cfg
echo ' option tcplog' >> /etc/haproxy/haproxy.cfg
echo ' tcp-request inspect-delay 5s' >> /etc/haproxy/haproxy.cfg
echo ' tcp-request content accept if HTTP' >> /etc/haproxy/haproxy.cfg
echo >> /etc/haproxy/haproxy.cfg
echo 'acl client_attempts_ssh payload(0,7) -m bin 5353482d322e30' >> /etc/haproxy/haproxy.cfg
echo >> /etc/haproxy/haproxy.cfg
echo 'use_backend ssh if !HTTP' >> /etc/haproxy/haproxy.cfg
echo ' use_backend ssh if client_attempts_ssh' >> /etc/haproxy/haproxy.cfg
echo ' use_backend secure_http if HTTP' >> /etc/haproxy/haproxy.cfg
systemctl restart haproxy.service
echo 'completed installing and configuring haproxy'
echo
echo '________________________________________________________________'
echo
echo 'installing apache2 web server'
apt-get install -y apache2
chmod -R 755 /var/www
systemctl restart apache2.service
echo 'completed installing apache'
echo
echo '________________________________________________________________'
echo
echo 'customizing ssh server configuration'
# backing up sshd_config
mv /etc/ssh/sshd_config /etc/ssh/sshd_config.old
# creating custom ssh_config
echo 'Port 22' > /etc/ssh/sshd_config
echo 'GatewayPorts yes' >> /etc/ssh/sshd_config
echo 'Protocol 2' >> /etc/ssh/sshd_config
echo 'HostKey /etc/ssh/ssh_host_rsa_key' >> /etc/ssh/sshd_config
echo 'HostKey /etc/ssh/ssh_host_dsa_key' >> /etc/ssh/sshd_config
echo 'HostKey /etc/ssh/ssh_host_ecdsa_key' >> /etc/ssh/sshd_config
echo 'HostKey /etc/ssh/ssh_host_ed25519_key' >> /etc/ssh/sshd_config
echo 'UsePrivilegeSeparation yes' >> /etc/ssh/sshd_config
echo 'KeyRegenerationInterval 3600' >> /etc/ssh/sshd_config
echo 'ServerKeyBits 1024' >> /etc/ssh/sshd_config
echo 'SyslogFacility AUTH' >> /etc/ssh/sshd_config
echo 'LogLevel VERBOSE' >> /etc/ssh/sshd_config
echo 'LoginGraceTime 120' >> /etc/ssh/sshd_config
echo 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config
echo 'StrictModes yes' >> /etc/ssh/sshd_config
echo 'RSAAuthentication yes' >> /etc/ssh/sshd_config
echo 'PubkeyAuthentication yes' >> /etc/ssh/sshd_config
echo 'IgnoreRhosts yes' >> /etc/ssh/sshd_config
echo 'RhostsRSAAuthentication no' >> /etc/ssh/sshd_config
echo 'HostbasedAuthentication no' >> /etc/ssh/sshd_config
echo 'PermitEmptyPasswords no' >> /etc/ssh/sshd_config
echo 'ChallengeResponseAuthentication no' >> /etc/ssh/sshd_config
echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config
echo 'X11Forwarding yes' >> /etc/ssh/sshd_config
echo 'X11DisplayOffset 10' >> /etc/ssh/sshd_config
echo 'PrintMotd no' >> /etc/ssh/sshd_config
echo 'PrintLastLog yes' >> /etc/ssh/sshd_config
echo 'TCPKeepAlive yes' >> /etc/ssh/sshd_config
echo 'AcceptEnv LANG LC_*' >> /etc/ssh/sshd_config
echo 'Subsystem sftp /usr/lib/openssh/sftp-server' >> /etc/ssh/sshd_config
echo 'UsePAM yes' >> /etc/ssh/sshd_config
echo 'TrustedUserCAKeys /etc/ssh/lightsail_instance_ca.pub' >> /etc/ssh/sshd_config
systemctl restart sshd.service
echo 'completed customizing ssh server'
echo
echo '________________________________________________________________'
echo
echo 'creating SSH trusted fingerprint for use by server and client to verify secure connections'
ssh-keyscan -t rsa localhost > /var/www/html/trusted
sed -i "s/localhost/$relay_fqdn/g" /var/www/html/trusted
chmod 755 /var/www/html/trusted
echo 'completed creating trusted fingerprint'
echo
echo '________________________________________________________________'
echo
echo 'installing mysql and setting up mattermost database'
apt-get install -y mysql-server
echo "create user 'mmuser'@'localhost' identified by '$mmuser_pass';" > /root/mysql.cfg
echo 'create database mattermost;' >> /root/mysql.cfg
echo "grant all privileges on mattermost.* to 'mmuser'@'localhost';" >> /root/mysql.cfg
echo 'exit' >> /root/mysql.cfg
mysql -u root -p$mysql_pass < /root/mysql.cfg
echo 'completed installing mysql and setting up mattermost database'
echo
echo '________________________________________________________________'
echo
echo 'installing and configuring mattermost service'
# used for collaboration
wget https://releases.mattermost.com/$mattermost_ver/mattermost-$mattermost_ver-linux-amd64.tar.gz
tar -xvzf mattermost-$mattermost_ver-linux-amd64.tar.gz 
mv mattermost /opt
mkdir /opt/mattermost/data
useradd --system --user-group mattermost
chown -R mattermost:mattermost /opt/mattermost
chmod -R g+w /opt/mattermost
# change default mattermost connection from docker test environment to local mysql install
sed -i "s|mostest@tcp(dockerhost:3306)/mattermost_test|$mmuser_pass@tcp(127.0.0.1:3306)/mattermost|" /opt/mattermost/config/config.json
# create mattermost service
echo '[Unit]' > /lib/systemd/system/mattermost.service
echo 'Description=Mattermost' >> /lib/systemd/system/mattermost.service
echo 'After=network.target' >> /lib/systemd/system/mattermost.service
echo 'After=mysql.service' >> /lib/systemd/system/mattermost.service
echo 'Requires=mysql.service' >> /lib/systemd/system/mattermost.service
echo >> /lib/systemd/system/mattermost.service
echo '[Service]' >> /lib/systemd/system/mattermost.service
echo 'Type=simple' >> /lib/systemd/system/mattermost.service
echo 'ExecStart=/opt/mattermost/bin/platform' >> /lib/systemd/system/mattermost.service
echo 'Restart=always' >> /lib/systemd/system/mattermost.service
echo 'RestartSec=10' >> /lib/systemd/system/mattermost.service
echo 'WorkingDirectory=/opt/mattermost' >> /lib/systemd/system/mattermost.service
echo 'User=mattermost' >> /lib/systemd/system/mattermost.service
echo 'Group=mattermost' >> /lib/systemd/system/mattermost.service
echo 'LimitNOFILE=49152' >> /lib/systemd/system/mattermost.service
echo >> /lib/systemd/system/mattermost.service
echo '[Install]' >> /lib/systemd/system/mattermost.service
echo 'WantedBy=multi-user.target' >> /lib/systemd/system/mattermost.service
echo 'reloading all services'
systemctl daemon-reload
systemctl start mattermost.service
systemctl enable mattermost.service
echo 'completed installing and configuring mattermost service'
echo
echo '________________________________________________________________'
echo
echo "adding limited user account $relay_user"
adduser --quiet --disabled-password --shell /bin/bash --home /home/$relay_user --gecos "Telesploit relay user" $relay_user
# create .ssh folder and authorized_keys file as the new user and set appropriate permissions
sudo -u $relay_user mkdir /home/$relay_user/.ssh/
sudo -u $relay_user touch /home/$relay_user/.ssh/authorized_keys
chmod 700 /home/$relay_user/.ssh/
chmod 600 /home/$relay_user/.ssh/authorized_keys
# disallow interactive logins for the new user (create tunnels only)
chsh -s /bin/false $relay_user
echo "completed adding $relay_user account"
echo
echo '________________________________________________________________'
echo
echo 'installing ircd-irc2'
# used for collaboration and update postings by scripts
apt-get install -y ircd-irc2
echo 'completed installing ircd'
echo
echo 'Reboot server to complete installation'
echo
