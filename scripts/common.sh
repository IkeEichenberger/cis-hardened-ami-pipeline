#!/usr/bin/env bash

echo -e "\e[32m################## COMMON ##################\e[0m"

# patch system
yum update -y

# add timestamp to history
echo 'export HISTTIMEFORMAT="%Y-%m-%d %k:%M:%S   "' > /etc/profile.d/historytimestamp.sh

# install Inspector agent for hardening tests (OPTIONAL)
cd /root
curl -sLO https://inspector-agent.amazonaws.com/linux/latest/install
chmod 750 install
./install

echo "Common script completed on `date`" >> /var/log/packer.log