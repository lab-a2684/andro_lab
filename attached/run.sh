#!/usr/bin/env bash
# Run the CVE-2024-23380 KGSL VBO bind UAF PoC from this bundle.
#
# This bundle is self-contained: the two kernel images, the device tree and the
# initramfs (which already carries busybox and the statically linked harness)
# are all prebuilt.  Nothing here compiles anything, and nothing is read from
# outside this directory.
#
# Usage:  ./run.sh vuln | fixed | both
#
# Env:    QEMU_TIMEOUT   seconds per run before the guest is killed (default 300)
#         KGSL_LOGLEVEL  kernel console loglevel (default 7; use 5 to match the
#                       shipped reference logs)
#         LAB_MEM        guest RAM (default 2G) -- must match the device tree
#         LAB_SMP        guest CPUs (default 4)  -- must match the device tree
#
# Exit:   0  if every run behaved as expected
#         1  if a run contradicted the expected verdict (see README.md)
set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

QEMU="${QEMU:-qemu-system-aarch64}"
MEM="${LAB_MEM:-2G}"
SMP="${LAB_SMP:-4}"
TIMEOUT="${QEMU_TIMEOUT:-300}"
LOGLEVEL="${KGSL_LOGLEVEL:-7}"
LOGS="$HERE/logs"

declare -A IMAGES
IMAGES[vuln]="$HERE/kernel/Image-vuln"
IMAGES[fixed]="$HERE/kernel/Image-fixed"
DTB="$HERE/dtb/cve-virt.dtb"
RAMDISK="$HERE/initramfs/ramdisk.cpio.gz"

die() { echo "ERROR: $*" >&2; exit 2; }

usage() {
	cat >&2 <<'EOF'
usage: ./run.sh vuln | fixed | both

  vuln    boot the vulnerable kernel (msm-5.10 @ 36f524a2)
  fixed   boot the fixed      kernel (msm-5.10 @ 44158877)
  both    run the differential and print a summary

Expected:  vuln  -> rc 0, "VERDICT: VULNERABLE"
           fixed -> rc 1, "VERDICT: NO UAF"
EOF
	exit 2
}

case "${1:-}" in
	vuln|fixed|both) MODE="$1" ;;
	*) usage ;;
esac

# --------------------------------------------------------------- preflight ---
[ -f "$RAMDISK" ] || die "missing initramfs: $RAMDISK (bundle is incomplete)"
[ -f "$DTB" ]      || die "missing device tree: $DTB (bundle is incomplete)"

for v in vuln fixed; do
	[ -f "${IMAGES[$v]}" ] || die "missing kernel: ${IMAGES[$v]} (bundle is incomplete)"
done

command -v "$QEMU" >/dev/null || die "$QEMU not found.
  Install QEMU for aarch64, e.g.:
      Debian/Ubuntu   sudo apt-get install qemu-system-arm
      Fedora          sudo dnf install qemu-system-aarch64
      Arch            sudo pacman -S qemu-system-arm
  Then re-run ./verify.sh"

mkdir -p "$LOGS"

# The device tree declares 4 x cortex-a57 and 2 GiB of RAM; the kernel is
# booted with -dtb, so it ignores the machine's generated topology.  A mismatch
# here is the single most common reason for a bundle that "does not boot".
grep -q 'arm,cortex-a57' "$HERE/audit/dt/cve-virt.dts" 2>/dev/null || true

# ------------------------------------------------------------------- runner ---
# $1 = variant.  Sets: RC[variant], HITS[variant], WRITES[variant]
declare -A RC HITS WRITES VERDICT

run_variant() {
	local v="$1"
	local image="${IMAGES[$v]}"
	local stamp log

	stamp="$(date -u +%Y%m%dT%H%M%SZ)"
	log="$LOGS/$v-$stamp.log"

	echo
	echo "================================================================"
	echo " $v   image: $image"
	echo " log:   $log"
	echo "================================================================"

	local -a cmd=(
		"$QEMU"
		-M virt,gic-version=2
		-cpu cortex-a57
		-smp "$SMP"
		-m "$MEM"
		-kernel "$image"
		-dtb "$DTB"
		-initrd "$RAMDISK"
		-append "console=ttyAMA0 earlycon=pl011,0x9000000 panic=-1 oops=panic loglevel=$LOGLEVEL kgsl.debug=mask=0x1ffffffff"
		-display none
		-serial stdio
		-monitor none
		-no-reboot
	)

	# Prefer timeout(1); fall back to a plain run if coreutils is unavailable.
	local -a wrap=()
	if command -v timeout >/dev/null 2>&1; then
		wrap=(timeout --foreground -k 10 "$TIMEOUT")
	fi

	local out rc=0
	set +e
	if [ "${#wrap[@]}" -gt 0 ]; then
		out="$("${wrap[@]}" "${cmd[@]}" 2>&1)" || rc=$?
	else
		out="$("${cmd[@]}" 2>&1)" || rc=$?
	fi
	set -e

	# The pl011 console under QEMU emits CRLF.  Normalise to LF, otherwise
	# every end-anchored pattern below silently fails to match.
	out="$(printf '%s\n' "$out" | tr -d '\r')"

	printf '%s\n' "$out" > "$log"

	# The harness prints its own rc; QEMU's exit status is not meaningful here
	# because the guest powers itself off.
	RC["$v"]="$(printf '%s\n' "$out" | sed -n 's/^--- harness exited rc=\([0-9]*\) ---$/\1/p' | tail -1)"
	[ -n "${RC[$v]}" ] || RC["$v"]="?"
	HITS["$v"]="$(printf '%s\n' "$out" | sed -n 's/.*UAF hits: \([0-9]*\).*/\1/p' | tail -1)"
	WRITES["$v"]="$(printf '%s\n' "$out" | sed -n 's/.*write-through hits: \([0-9]*\).*/\1/p' | tail -1)"
	VERDICT["$v"]="$(printf '%s\n' "$out" | sed -n 's/^ VERDICT: \([A-Z ]*\).*/\1/p' | tail -1 | sed 's/ *$//')"

	# Echo the parts of the guest console that matter, not 100 KB of kernel log.
	printf '%s\n' "$out" | grep -E '^\[\+\]|^\[\-\]|^ (attempts|VERDICT):|^--- ' || true

	if printf '%s\n' "$out" | grep -q '^=== lab complete ===$'; then
		echo " (guest reached 'lab complete'; full console in $log)"
	else
		echo " (guest did NOT reach 'lab complete'; full console in $log)"
	fi

	# 124 is timeout(1)'s "I killed it".  Say so, because a truncated run
	# must never be mistaken for a clean result.
	if [ "$rc" = 124 ]; then
		echo " (WARNING: killed after ${TIMEOUT}s -- the run did not finish;"
		echo "  raise QEMU_TIMEOUT, and treat any counts below as a lower bound)"
	fi
}

# --------------------------------------------------------------------- main ---
echo "== bundle:  $HERE"
echo "== qemu:    $("$QEMU" --version 2>/dev/null | head -1)"
echo "== machine: virt  cpu=cortex-a57  smp=$SMP  mem=$MEM  gic=v2"
echo "== loglevel: $LOGLEVEL   timeout: ${TIMEOUT}s"

case "$MODE" in
	vuln|fixed)
		run_variant "$MODE"
		;;
	both)
		run_variant vuln
		run_variant fixed
		;;
esac

# ----------------------------------------------------------------- summary ---
echo
echo "================================================================"
echo " SUMMARY"
echo "================================================================"
printf ' %-7s %-10s %-12s %-16s %s\n' VARIANT "harness rc" "UAF hits" "write-through" VERDICT
for v in vuln fixed; do
	printf ' %-7s %-10s %-12s %-16s %s\n' \
		"$v" "${RC[$v]}" "${HITS[$v]:-?}" "${WRITES[$v]:-?}" "${VERDICT[$v]:-?}"
done
echo

rc=0
case "$MODE" in
	vuln|fixed)
		v="$MODE"
		if [ "$v" = vuln ]; then
			if [ "${RC[$v]}" = 0 ] && [ "${HITS[$v]:-0}" -gt 0 ] 2>/dev/null; then
				echo " OK: vulnerable kernel reported the UAF, as expected."
			else
				echo " UNEXPECTED: expected rc=0 and >0 UAF hits on the vulnerable kernel."
				echo "             0 hits usually means the race lost its timing window on"
				echo "             this host, not that the bug is absent. See README.md."
				rc=1
			fi
		else
			if [ "${RC[$v]}" = 1 ] && [ "${HITS[$v]:-1}" = 0 ]; then
				echo " OK: fixed kernel reported no UAF, as expected."
			else
				echo " UNEXPECTED: the fixed kernel reported the UAF. That contradicts"
				echo "             the upstream fix; please report it with the log."
				rc=1
			fi
		fi
		;;
	both)
		ok=1
		[ "${RC[vuln]:-x}"  = 0 ] && [ "${HITS[vuln]:-0}" -gt 0 ] 2>/dev/null || ok=0
		[ "${RC[fixed]:-x}" = 1 ] && [ "${HITS[fixed]:-1}" = 0 ] || ok=0
		if [ "$ok" = 1 ]; then
			echo " OK: differential reproduced."
			echo "     Vulnerable 36f524a2 -> UAF present (read AND write through the stale PTE)."
			echo "     Fixed      44158877 -> UAF absent."
			echo "     The only kernel-side difference between the two images is the"
			echo "     upstream kgsl_vbo.c fix. See SUMMARY.md."
		else
			echo " UNEXPECTED: the differential did not reproduce as documented."
			echo "             See README.md 'If the vulnerable kernel reports 0 hits'."
			rc=1
		fi
		;;
esac

echo
echo "Logs: $LOGS"
[ "$rc" -eq 0 ] && echo "Result: as documented." || echo "Result: see above."
exit "$rc"
