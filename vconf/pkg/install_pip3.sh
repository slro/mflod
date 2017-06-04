#!/usr/bin/env bash

# cd to import directory
cd /vagrant/vconf || exit 1
source provision_helper.sh
REQ_FILE_PATH=/vagrant/requirements.txt

install_package 'pip3' "
apt-get install -y python3-pip
"

# install packages from freezed requirements
if [[ $? -ne 0 ]]; then exit 1; fi
if [[ -s ${REQ_FILE_PATH} ]]; then
    pip3 install -r ${REQ_FILE_PATH}
fi
