#!/usr/bin/env bash

# cd to import directory
cd /vagrant/vconf || exit 1
source provision_helper.sh

install_package 'python3 -c "import unittest_data_provider"' 'unittest_data_provider' "
pip3 install unittest_data_provider
"
