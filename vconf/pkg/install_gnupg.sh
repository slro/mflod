#!/usr/bin/env bash

# cd to import directory
cd /vagrant/vconf || exit 1
source provision_helper.sh

install_package 'python3 -c "import gnupg"' 'python3-gnupg' "
apt install -y python3-gnupg
"
