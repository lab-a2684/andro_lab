#!/usr/bin/env bash
# Configure and build the pinned msm-5.10 kernel for the CVE-2024-23380 lab.
#
# Usage:  ./build/kernel.sh [defconfig|olddefconfig|Image|dtbs|modules|all]
#
# Out-of-tree (O=) so the pinned snapshot on disk is never modified.
set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$HERE/env.sh"

FRAG="${FRAG:-$CVE_DIR/config/frag-cve.config}"

case "${1:-all}" in
  defconfig)
    kbuild defconfig
    "$KSRC/scripts/kconfig/merge_config.sh" -m -O "$KOUT" "$KOUT/.config" "$FRAG"
    kbuild olddefconfig
    ;;
  olddefconfig)
    kbuild olddefconfig
    ;;
  Image)
    kbuild -j"$JOBS" Image
    ;;
  dtbs)
    kbuild -j"$JOBS" dtbs
    ;;
  modules)
    kbuild -j"$JOBS" modules
    ;;
  all)
    kbuild -j"$JOBS" Image dtbs modules
    ;;
  *)
    kbuild -j"$JOBS" "$@"
    ;;
esac
