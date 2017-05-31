#!/usr/bin/env bash

# cd to import directory
cd /vagrant/vconf || exit 1
source provision_helper.sh

install_package 'python3 -c "import pyasn1"' 'pyasn1' "
pacman -S --noconfirm python-pyasn1
"
