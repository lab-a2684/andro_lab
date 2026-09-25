#!/usr/bin/env bash
# Prove that the code carrying CVE-2024-23380 is byte-identical to the pinned
# upstream tarball.
#
# The lab is allowed to add hardware-adaptation shims.  It is not allowed to
# change the logic that contains the bug.  This script re-extracts the pinned
# tarball and diffs the protected files, so the claim is checkable rather than
# asserted.  Run it after any change to the snapshots.
#
# Usage:  ./build/verify-protected.sh [vuln|fixed]
set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CVE_DIR="$(cd "$HERE/.." && pwd)"
WORK="$CVE_DIR/.work"

# Files whose bytes define the vulnerability.  Anything listed here must match
# the pinned tarball exactly.
PROTECTED=(
  drivers/gpu/msm/kgsl_vbo.c
  drivers/gpu/msm/kgsl_mmu.c
  drivers/gpu/msm/kgsl_iommu.c
  drivers/gpu/msm/kgsl_sharedmem.c
  drivers/gpu/msm/kgsl_pool.c
  drivers/gpu/msm/kgsl_reclaim.c
  drivers/gpu/msm/kgsl_ioctl.c
  drivers/gpu/msm/adreno.c
)

declare -A TARBALL=(
  [vuln]="$WORK/archives/msm-5.10-36f524a.tar.gz"
  [fixed]="$WORK/archives/msm-5.10-44158877.tar.gz"
)

declare -A SNAPSHOT=(
  [vuln]="$WORK/snapshots/msm-5.10-vulnerable"
  [fixed]="$WORK/snapshots/msm-5.10-fixed"
)

VARIANT="${1:-vuln}"
case "$VARIANT" in
  vuln|fixed) ;;
  *) echo "unknown variant '$VARIANT' (want vuln or fixed)" >&2; exit 2 ;;
esac

TAR="${TARBALL[$VARIANT]}"
SNAP="${SNAPSHOT[$VARIANT]}"

[ -f "$TAR" ]  || { echo "missing tarball: $TAR" >&2; exit 2; }
[ -d "$SNAP" ] || { echo "missing snapshot: $SNAP" >&2; exit 2; }

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

patterns=()
for f in "${PROTECTED[@]}"; do patterns+=("*/$f"); done

tar -xzf "$TAR" -C "$SCRATCH" --wildcards "${patterns[@]}"

# The tarball has a single top-level directory named after the commit.
upstream_root="$(find "$SCRATCH" -mindepth 1 -maxdepth 1 -type d | head -1)"

echo "== protected-file check: $VARIANT"
echo "== tarball: $TAR"
echo "== snapshot: $SNAP"
echo

rc=0
for f in "${PROTECTED[@]}"; do
  up="$upstream_root/$f"
  ours="$SNAP/$f"

  if [ ! -f "$up" ] || [ ! -f "$ours" ]; then
    printf 'MISSING  %s\n' "$f"
    rc=1
    continue
  fi

  up_sum="$(sha256sum "$up"   | cut -d' ' -f1)"
  our_sum="$(sha256sum "$ours" | cut -d' ' -f1)"

  if [ "$up_sum" = "$our_sum" ]; then
    printf 'IDENTICAL %s  %s\n' "${up_sum:0:16}" "$f"
  else
    printf 'DIFFERS   %s  %s\n' "${up_sum:0:16}" "$f"
    diff -u "$up" "$ours" | head -40 || true
    rc=1
  fi
done

echo
if [ "$rc" -eq 0 ]; then
  echo "PASS: all ${#PROTECTED[@]} protected files match the pinned tarball byte for byte."
else
  echo "FAIL: at least one protected file has been modified."
fi
exit "$rc"
