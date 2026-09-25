#!/usr/bin/env bash
# Build the CVE-2024-23380 user-space harness for aarch64.
#
# Two things matter here:
#
#   * The KGSL UAPI comes from the pinned kernel snapshot's include/uapi, not
#     from a system header and not from copy-pasted struct definitions.  That
#     is what guarantees the ioctl numbers and struct layouts the harness
#     uses are exactly the ones the kernel under test implements.
#
#   * The binary is statically linked.  The initramfs carries only busybox,
#     so there is no dynamic loader or libc in the guest.
#
# Usage:  ./build/harness.sh [variant]     (default: vuln)
set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CVE_DIR="$(cd "$HERE/.." && pwd)"

VARIANT="${1:-vuln}"
case "$VARIANT" in
vuln|fixed) ;;
*) echo "unknown variant: $VARIANT (want vuln|fixed)" >&2; exit 2 ;;
esac

UAPI="$CVE_DIR/.work/snapshots/msm-$([ "$VARIANT" = fixed ] && \
	echo 5.10-fixed || echo 5.10-vulnerable)/include/uapi"
[ -f "$UAPI/linux/msm_kgsl.h" ] || {
	echo "missing pinned UAPI header: $UAPI/linux/msm_kgsl.h" >&2
	exit 2
}

CC="${CC:-aarch64-linux-gnu-gcc}"
command -v "$CC" >/dev/null || { echo "missing $CC" >&2; exit 2; }

OUT="$HERE/harness/poc"
mkdir -p "$HERE/harness"

# Put msm_kgsl.h in an include root of its own.  Pointing -I straight at the
# snapshot's include/uapi would shadow libc's own linux/types.h with the
# kernel's, which is not usable from user space; staging just the one header
# means its nested includes fall through to the system headers, which is
# exactly what we want.  Symlinked, so it is always the pinned bytes.
SHIM="$HERE/harness/uapi"
mkdir -p "$SHIM/linux"
ln -sfn "$UAPI/linux/msm_kgsl.h" "$SHIM/linux/msm_kgsl.h"

echo "== variant:  $VARIANT"
echo "== uapi:     $(readlink -f "$SHIM/linux/msm_kgsl.h")"
echo "== compiler: $($CC --version | head -1)"

"$CC" \
	-std=gnu11 -O2 -g -Wall -Wextra -Wno-unused-parameter \
	-static \
	-I"$SHIM" \
	-I"$HERE/harness" \
	-o "$OUT" \
	"$HERE/harness/poc.c" \
	-lpthread

echo "== built: $OUT"
file "$OUT"
echo "== size:  $(stat -c %s "$OUT") bytes"
