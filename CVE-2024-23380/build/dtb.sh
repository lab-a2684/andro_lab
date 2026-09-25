#!/usr/bin/env bash
# Compile dt/cve-virt.dts to dt/cve-virt.dtb.
set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CVE_DIR="$(cd "$HERE/.." && pwd)"

command -v dtc >/dev/null || { echo "missing dtc" >&2; exit 2; }

DTS="$CVE_DIR/dt/cve-virt.dts"
DTB="$CVE_DIR/dt/cve-virt.dtb"

echo "== dtc:  $(dtc --version)"
echo "== in:   $DTS"

# -Wno-unit_address_vs_reg etc. are deliberately not suppressed: this tree is
# hand-written, so every warning here is a real mistake in the tree.
dtc \
	-I dts \
	-O dtb \
	-o "$DTB" \
	"$DTS"

echo "== out:  $DTB ($(stat -c %s "$DTB") bytes)"
