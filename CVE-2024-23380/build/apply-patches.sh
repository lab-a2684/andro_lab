#!/usr/bin/env bash
# Apply the lab's patches to a pinned snapshot.
#
# The snapshots under .work/snapshots are the pinned upstream tarballs plus the
# explicit lab patches in patches/. They are the only place the lab touches
# kernel source, and every change is reviewable as a diff. Nothing here edits a
# protected file; build/verify-protected.sh checks that afterwards.
#
# Usage:  ./build/apply-patches.sh [vuln|fixed] [--check]
#
#   --check   report what is applied without modifying anything
set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CVE_DIR="$(cd "$HERE/.." && pwd)"
WORK="$CVE_DIR/.work"
PATCH_DIR="${PATCH_DIR:-$CVE_DIR/patches}"

declare -A SNAPSHOT=(
  [vuln]="$WORK/snapshots/msm-5.10-vulnerable"
  [fixed]="$WORK/snapshots/msm-5.10-fixed"
)

VARIANT="${1:-vuln}"
case "$VARIANT" in
  vuln|fixed) ;;
  *) echo "unknown variant '$VARIANT' (want vuln or fixed)" >&2; exit 2 ;;
esac

MODE=apply
for arg in "$@"; do
  case "$arg" in
    --check) MODE=check ;;
  esac
done

SNAP="${SNAPSHOT[$VARIANT]}"
[ -d "$SNAP" ] || { echo "missing snapshot: $SNAP" >&2; exit 2; }

# Ordered, numerically prefixed patches.
patches=()
while IFS= read -r p; do patches+=("$p"); done < <(
  find "$PATCH_DIR" -maxdepth 1 -name '*.patch' -type f | sort
)

if [ "${#patches[@]}" -eq 0 ]; then
  echo "no patches found in $PATCH_DIR"
  exit 0
fi

rc=0
for p in "${patches[@]}"; do
  name="$(basename "$p")"
  printf '%-10s %-8s %s\n' "$VARIANT" "$MODE" "$name"

  # patch(1) narrates reverse matches and skipped hunks on stdout and stderr
  # even with --silent; the dry runs below only care about the exit status.
  if (patch -d "$SNAP" -p1 --dry-run --forward --silent < "$p") >/dev/null 2>&1; then
    [ "$MODE" = check ] && continue
    patch -d "$SNAP" -p1 --forward --silent < "$p"
  elif (patch -d "$SNAP" -p1 --dry-run --reverse --forward --silent < "$p") >/dev/null 2>&1; then
    echo "           (already applied)"
  else
    echo "           DOES NOT APPLY" >&2
    rc=1
  fi
done

if [ "$MODE" != check ]; then
  echo
  echo "verifying protected files are still byte-identical to the pinned tarball:"
  "$HERE/verify-protected.sh" "$VARIANT" || rc=1
fi

exit "$rc"
