#!/usr/bin/env bash

# cd to import directory
cd /vagrant/vconf || exit 1
source provision_helper.sh

install_package 'python3 -c "from cryptography.fernet import Fernet' 'cryptography' "
pip3 install -U pip;
pip3 install cryptography
"