# telesploit-relay
 Script to create an open source Telesploit relay

Tested on Amazon Lightsail - Ubuntu 18.04
Recommended instance 1GB memory, 1 vCPU, 40GB SSD or greater

Create an A record for the relay FQDN.

Verify that ports 22, 80, and 443 are open on any firewalls. Port 80 may be closed after running relay_setup.sh (required by Let's Encrypt).

From the relay run 'git clone https://github.com/telesploit/telesploit-relay.git'

Change into the telesploit-relay directory and run relay_setup.sh as root

Once the Telesploit server and client are setup, add their SSH public keys to /home/telesploit-relay/.ssh/authorized_keys (default install)

