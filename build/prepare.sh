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




#rm -rf ${SCRIPT_DIR}/rootfs
#rm -rf ${SCRIPT_DIR}/fake.db
#mkdir -p ${SCRIPT_DIR}/rootfs
# ${SCRIPT_DIR}/../src/proot -s ${SCRIPT_DIR}/fake.db -0 -w / -b /proc -b /sys -b /dev /bin/bash -c "
# tar zxvf ${SCRIPT_DIR}/ubuntu-base-24.04.2-base-arm64.tar.gz  -p --same-owner --numeric-owner --xattrs -C ${SCRIPT_DIR}/rootfs/
# "
sed -i 's/ports.ubuntu.com/mirrors.tuna.tsinghua.edu.cn/g' ${SCRIPT_DIR}/rootfs/etc/apt/sources.list.d/ubuntu.sources
sed -i 's/security.ubuntu.com/mirrors.tuna.tsinghua.edu.cn/g' ${SCRIPT_DIR}/rootfs/etc/apt/sources.list.d/ubuntu.sources

# strace -o log.txt
# cp /usr/bin/qemu-aarch64-static ${SCRIPT_DIR}/rootfs/usr/bin
# mkdir -p ${SCRIPT_DIR}/rootfs/proc/sys/fs/binfmt_misc
# unshare --user --mount --map-root-user /bin/bash -c "
# set -ex
# mount --rbind /dev ${SCRIPT_DIR}/rootfs/dev
# mount --rbind /sys ${SCRIPT_DIR}/rootfs/sys
# mount --rbind /proc ${SCRIPT_DIR}/rootfs/proc
# ls -al ${SCRIPT_DIR}/rootfs/proc/sys/fs/binfmt_misc
# chroot ${SCRIPT_DIR}/rootfs /bin/bash -c '
# cd /root
# ls -al /var/lib/dpkg/status
# echo ------------
# ls -al /var/lib/dpkg/status-old
# echo ------------
# /usr/bin/qemu-aarch64-static -strace -D log.txt /usr/bin/dpkg --force-depends  -i systemd_255.4-1ubuntu8.6_arm64.deb
# '
# exit 1
# "