#!/bin/bash
set -ex

SCRIPT_PATH="${BASH_SOURCE}"
while [ -L "${SCRIPT_PATH}" ]; do
  SCRIPT_DIR="$(cd -P "$(dirname "${SCRIPT_PATH}")" >/dev/null 2>&1 && pwd)"
  SCRIPT_PATH="$(readlink "${SCRIPT_PATH}")"
  [[ ${SCRIPT_PATH} != /* ]] && SCRIPT_PATH="${SCRIPT_DIR}/${SCRIPT_PATH}"
done
SCRIPT_PATH="$(readlink -f "${SCRIPT_PATH}")"
SCRIPT_DIR="$(cd -P "$(dirname -- "${SCRIPT_PATH}")" >/dev/null 2>&1 && pwd)"




rm -rf ${SCRIPT_DIR}/rootfs
rm -rf ${SCRIPT_DIR}/fake.db
mkdir -p ${SCRIPT_DIR}/rootfs
# ${SCRIPT_DIR}/../src/proot -s ${SCRIPT_DIR}/fake.db -0 -w / -b /proc -b /sys -b /dev /bin/bash -c "
tar zxvf ${SCRIPT_DIR}/ubuntu-base-24.04.2-base-arm64.tar.gz  -p --same-owner --numeric-owner --xattrs -C ${SCRIPT_DIR}/rootfs/
# "
sed -i 's/ports.ubuntu.com/mirrors.tuna.tsinghua.edu.cn/g' ${SCRIPT_DIR}/rootfs/etc/apt/sources.list.d/ubuntu.sources
sed -i 's/security.ubuntu.com/mirrors.tuna.tsinghua.edu.cn/g' ${SCRIPT_DIR}/rootfs/etc/apt/sources.list.d/ubuntu.sources

