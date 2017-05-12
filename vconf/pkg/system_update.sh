#!/usr/bin/env bash

echo ' >> RUNNING SYSTEM UPDATE ...'
sudo apt-get -y update > /dev/null 2>&1
sudo apt-get -y upgrade > /dev/null 2>&1
# Upgrade pip to newest version
pip3 install -U pip
