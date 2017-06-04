#!/usr/bin/env bash

# cd to import directory
cd /vagrant/vconf || exit 1
source provision_helper.sh

install_package 'python3 -c "import pkg_resources;pkg_resources.require('pyasn1==0.2.3');import pyasn1"
"' 'pyasn1' "
pip3 uninstall -y pyasn1;
pip3 install -U pip;
pip3 install pyasn1
"
