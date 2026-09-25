#!/usr/bin/env bash
# Shared build settings for the CVE-2024-23380 lab.
#
# Kernel source is the pinned VULNERABLE or FIXED snapshot. Builds are
# out-of-tree (O=), while any lab adaptation is applied only through the
# explicit, reviewable patches under patches/. The files carrying the
# vulnerability are checked byte-for-byte by verify-protected.sh.

set -Eeuo pipefail

CVE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export CROSS_COMPILE="${CROSS_COMPILE:-aarch64-linux-gnu-}"
export ARCH="${ARCH:-arm64}"

VARIANT="${VARIANT:-vuln}"

case "$VARIANT" in
  vuln)
    KSRC="${KSRC:-$CVE_DIR/.work/snapshots/msm-5.10-vulnerable}"
    ;;
  fixed)
    KSRC="${KSRC:-$CVE_DIR/.work/snapshots/msm-5.10-fixed}"
    ;;
  *)
    KSRC="${KSRC:?unknown variant '$VARIANT'}"
    ;;
esac

KOUT="${KOUT:-$CVE_DIR/out/$VARIANT}"
export KOUT KSRC

JOBS="${JOBS:-4}"
export JOBS

# This tree is Android 12 (5.10), pinned to a hermetic Clang r416183b build.
# Two things stand between it and a clean build with the distro GCC 13 that is
# actually installed here:
#
#  1. CONFIG_WERROR=y in arch/arm64/configs/defconfig, now turned off in
#     config/frag-cve.config.
#
#  2. scripts/basic/cc-wrapper.c, a Qualcomm downstream addition, replaces
#     $(CC) with a proxy that turns *any* compiler warning into a build
#     failure.  Its allow-list is three hard-coded source locations.  GCC 13
#     warns about things Clang r416183b did not: a format string with extra
#     arguments in kgsl_pwrctrl.c, a pointer printed with %x in bam_dma.c,
#     statics and variables that are unused under this config, and so on.
#
# There is no switch to relax the wrapper, and patching it would mean editing
# the pinned snapshot.  Instead pass -w, which lands at the very end of the
# command line (Makefile: "KBUILD_CFLAGS += $(KCFLAGS)" is the last assignment)
# and silences the categories Clang never produced.
#
# Consequence: a normal build here reports no warnings at all, including from
# our own shim.  build/shim-warnings.sh re-compiles the lab's own files with
# warnings enabled so regressions there are still caught.
KCFLAGS="${KCFLAGS:-} -w"
export KCFLAGS

kbuild() {
  make -C "$KSRC" O="$KOUT" ARCH=arm64 CROSS_COMPILE="$CROSS_COMPILE" \
       "KCFLAGS=$KCFLAGS" "$@"
}
export -f kbuild 2>/dev/null || true
