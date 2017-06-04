#!/usr/bin/env bash

echo ' >> RUNNING SYSTEM UPDATE ...'
sudo pacman -S --noconfirm archlinux-keyring > /dev/null 2>&1
sudo pacman -Syu --noconfirm --ignore ca-certificates-utils > /dev/null 2>&1
sudo rm /etc/ssl/certs/ca-certificates.crt > /dev/null 2>&1
sudo pacman -S --noconfirm ca-certificates-utils > /dev/null 2>&1


