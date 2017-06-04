#!/usr/bin/env bash

# cd to import directory
cd /vagrant/vconf || exit 1
source provision_helper.sh

install_package 'python3 -c "import pkg_resources;pkg_resources.require('cryptography==1.9');import cryptography"
"' 'cryptography' "
pip3 uninstall -y cryptography;
pip3 install -U pip;
pip3 install cryptography
"