#!/bin/bash

set -ex
# pwd
# cd /
# pwd
# echo 123
# touch /test
# #useradd liuyawu
# chown liuyawu:liuyawu /test
# ls -al /test
# chmod 777 /test
# ls -al /test

export DEBIAN_FRONTEND=noninteractive
apt update -y
cd /root
# apt download systemd -y
# # apt upgrade -y
# apt --fix-broken install -y
# dpkg --force-depends  -i systemd_255.4-1ubuntu8.6_arm64.deb 
#/usr/bin/qemu-aarch64-static -strace -D log.txt /usr/bin/dpkg --force-all  -i systemd_255.4-1ubuntu8.6_arm64.deb
# dpkg --force-all  -i systemd_255.4-1ubuntu8.6_arm64.deb
apt install systemd systemd-sysv -y
apt install rsyslog -y
ls /usr/bin/systemd-cat