#!/usr/bin/env bash

# cd to import directorypip
cd /vagrant/vconf || exit 1
source provision_helper.sh

install_package 'python3 -c "import pgpdump"' 'pgpdump' "
pip3 install -U pip;
pip3 install pgpdump
"
