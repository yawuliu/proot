#!/bin/bash

set -ex


tar zxf build/ubuntu-base-24.04.2-base-arm64.tar.gz  -p --same-owner --numeric-owner --xattrs -C build/rootfs/
# strace  1>strace.log 2>&1
