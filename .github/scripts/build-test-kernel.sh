#!/usr/bin/env bash
set -euo pipefail
version="$1"
work="$2"
case "$version" in
  5.4.290) checksum=6cc73cf2a7f50580f7d8c7e99d2f2e8ada8b7d2f4e76f5896f0daf691cc2a456 ;;
  5.10.240) checksum=8d88c3977226d666554b75f480d1e6c5f4e4d2acdf2a3462840c6bac88634d13 ;;
  6.6.110) checksum=1bf20daf5543b8759f325e55fb0da4913715e68741627a13380e66aaf219fb1d ;;
  *) echo "unsupported test kernel: $version" >&2; exit 1 ;;
esac
mkdir -p "$work"
curl --fail --location --retry 3 "https://cdn.kernel.org/pub/linux/kernel/v${version%%.*}.x/linux-$version.tar.xz" -o "$work/kernel.tar.xz"
printf '%s  %s\n' "$checksum" "$work/kernel.tar.xz" | sha256sum --check
tar -xJf "$work/kernel.tar.xz" -C "$work"
cd "$work/linux-$version"
make x86_64_defconfig
scripts/config --disable DEBUG_INFO --disable DEBUG_INFO_BTF --disable SECURITY_SELINUX \
  --enable BPF --enable BPF_SYSCALL --enable BPF_JIT --enable BPF_EVENTS \
  --enable CGROUPS --enable CGROUP_BPF --enable NET_NS --enable VETH --enable DUMMY \
  --enable NET_SCHED --enable NET_CLS_BPF --enable NET_CLS_ACT --enable NET_SCH_INGRESS \
  --enable NET_CLS_U32 --enable NET_ACT_BPF --enable NET_ACT_MIRRED \
  --enable NETFILTER --enable NF_CONNTRACK --enable NF_NAT --enable IP_NF_IPTABLES \
  --enable IP_NF_FILTER --enable IP_NF_NAT --enable IP_NF_TARGET_MASQUERADE \
  --enable IPV6 --enable IP_ADVANCED_ROUTER --enable IP_MULTIPLE_TABLES --enable IPV6_MULTIPLE_TABLES \
  --enable VIRTIO --enable VIRTIO_PCI --enable VIRTIO_CONSOLE --enable VIRTIO_NET \
  --enable NET_9P --enable NET_9P_VIRTIO --enable 9P_FS --enable DEVTMPFS --enable DEVTMPFS_MOUNT
make olddefconfig
make -j"$(nproc)" bzImage
cp arch/x86/boot/bzImage "$work/bzImage"
cp .config "$work/kernel.config"
