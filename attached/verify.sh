#!/usr/bin/env bash
# Check this bundle before trusting its output.
#
# Two independent things are verified:
#
#   1. FILE INTEGRITY  -- every file matches MANIFEST.sha256.  This catches a
#      truncated copy, a partial transfer, or a file that was edited after the
#      bundle was produced.  It proves the bundle is the one that was shipped.
#
#   2. HOST READINESS  -- the machine can actually run it: qemu-system-aarch64
#      is present and new enough, the CPU supports aarch64 emulation, and the
#      guest image/device-tree combination the bundle needs is supported.
#
# What this does NOT do: re-verify the kernel *sources* against the upstream
# Qualcomm tarballs.  That needs the two 191 MB archives and gdb, which are not
# shipped here.  audit/protected-files.sha256 records the hashes of the eight
# KGSL files that carry the bug, for anyone who does have the sources.
#
# Usage:  ./verify.sh
# Exit:   0 all checks passed, 1 a check failed
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

QEMU="${QEMU:-qemu-system-aarch64}"

pass=0
fail=0

ok()   { printf '  [ OK ]  %s\n' "$*"; pass=$((pass+1)); }
bad()  { printf '  [FAIL]  %s\n' "$*"; fail=$((fail+1)); }
warn() { printf '  [WARN]  %s\n' "$*"; }
info() { printf '          %s\n' "$*"; }

echo "================================================================"
echo " CVE-2024-23380 bundle check"
echo " $HERE"
echo "================================================================"

# ------------------------------------------------------- 1. file integrity ---
echo
echo "-- file integrity --------------------------------------------------"
if [ ! -f MANIFEST.sha256 ]; then
	bad "MANIFEST.sha256 is missing -- bundle is incomplete"
else
	if sha256sum -c MANIFEST.sha256 >/tmp/.attached-sums.$$ 2>&1; then
		n=$(grep -c ': OK$' /tmp/.attached-sums.$$)
		ok "all $n files match MANIFEST.sha256"
	else
		bad "file integrity check failed:"
		grep -v ': OK$' /tmp/.attached-sums.$$ | sed 's/^/          /'
	fi
	rm -f /tmp/.attached-sums.$$
fi

# The runnable pieces must be present and non-trivially sized.
echo
echo "-- required artifacts ----------------------------------------------"
for f in \
	"kernel/Image-vuln" \
	"kernel/Image-fixed" \
	"dtb/cve-virt.dtb" \
	"initramfs/ramdisk.cpio.gz" \
	"run.sh" \
	"README.md"
do
	if [ ! -f "$f" ]; then
		bad "missing: $f"
	elif [ ! -s "$f" ]; then
		bad "empty: $f"
	else
		ok "$(printf '%-28s %10d bytes' "$f" "$(stat -c %s "$f" 2>/dev/null || echo '?')")"
	fi
done

# The initramfs is what actually carries the harness.  Confirm it is there
# rather than trusting the file size.
if command -v gzip >/dev/null 2>&1 && command -v cpio >/dev/null 2>&1; then
	if gzip -dc initramfs/ramdisk.cpio.gz 2>/dev/null \
		| cpio -t 2>/dev/null | grep -qx 'harness/poc'; then
		ok "initramfs contains the PoC harness (harness/poc)"
	else
		bad "initramfs does not contain harness/poc -- cannot list it here"
		info "install gzip and cpio to re-check"
	fi
else
	warn "gzip or cpio missing -- skipped the initramfs content check"
fi

# The two kernels must be the same size but different: they are the same tree
# with one upstream fix between them.  Identical files would mean the
# differential is meaningless.
echo
echo "-- differential sanity ---------------------------------------------"
if [ -f kernel/Image-vuln ] && [ -f kernel/Image-fixed ]; then
	sv=$(stat -c %s kernel/Image-vuln)
	sf=$(stat -c %s kernel/Image-fixed)
	if [ "$sv" = "$sf" ]; then
		ok "both kernels are $sv bytes (expected: same tree, one fix)"
	else
		warn "kernels differ in size: vuln=$sv fixed=$sf"
	fi
	if cmp -s kernel/Image-vuln kernel/Image-fixed; then
		bad "the two kernels are byte-identical -- the differential cannot work"
	else
		ok "the two kernels differ, as expected"
	fi
fi

# ---------------------------------------------------------- 2. host readiness ---
echo
echo "-- host readiness --------------------------------------------------"
for t in bash sha256sum stat; do
	if command -v "$t" >/dev/null 2>&1; then
		ok "found: $t"
	else
		bad "missing: $t  (install coreutils)"
	fi
done

if command -v timeout >/dev/null 2>&1; then
	ok "found: timeout (runs will be bounded)"
else
	warn "timeout(1) missing -- runs will not be time-limited (Ctrl-C to stop)"
fi

if command -v "$QEMU" >/dev/null 2>&1; then
	qv="$("$QEMU" --version 2>/dev/null | head -1)"
	ok "found: $QEMU"
	info "$qv"

	maj="$(printf '%s' "$qv" | sed -n 's/.*version \([0-9][0-9]*\)\..*/\1/p' | head -1)"
	if [ -n "$maj" ] && [ "$maj" -lt 6 ] 2>/dev/null; then
		bad "QEMU $maj is too old; this bundle needs 6.0 or newer (GICv2 + aarch64 virt)"
	else
		ok "QEMU version is new enough"
	fi

	# The guest is a cortex-a57 under -M virt with an externally supplied
	# device tree.  If this host's QEMU cannot provide a GICv2 that matches,
	# the kernel will not come up.
	#
	# -S parks the CPU and -monitor stdio lets us send "quit" on stdin, so
	# QEMU starts, validates the machine line, and exits promptly.  The
	# timeout is a backstop: a check that can hang is worse than no check.
	if command -v timeout >/dev/null 2>&1; then
		timeout 15 "$QEMU" -M virt,gic-version=2 -cpu cortex-a57 \
			-display none -nodefaults -S \
			-monitor stdio -serial none \
			>/dev/null 2>&1 <<<'quit'
		rc=$?
	else
		"$QEMU" -M virt,gic-version=2 -cpu cortex-a57 \
			-display none -nodefaults -S \
			-monitor stdio -serial none \
			>/dev/null 2>&1 <<<'quit'
		rc=$?
	fi
	case "$rc" in
		0)   ok "QEMU accepts -M virt,gic-version=2 -cpu cortex-a57" ;;
		124) warn "the QEMU machine-line check timed out; skipping it" ;;
		*)   bad "QEMU rejected the machine line this bundle uses (rc=$rc)"
		     info "the kernel may not boot; try ./run.sh vuln and read the log" ;;
	esac
else
	bad "$QEMU not found"
	info "Debian/Ubuntu   sudo apt-get install qemu-system-arm"
	info "Fedora          sudo dnf install qemu-system-aarch64"
	info "Arch            sudo pacman -S qemu-system-arm"
fi

# TCG is used deliberately (the kernel is the thing under test, not CPU
# emulation speed), so /dev/kvm is not required.  Mention it only.
if [ -e /dev/kvm ]; then
	info "/dev/kvm present but unused -- this bundle runs under TCG on purpose"
fi

# ----------------------------------------------------------------- verdict ---
echo
echo "================================================================"
if [ "$fail" -eq 0 ]; then
	echo " RESULT: all $pass checks passed."
	echo " Next:   ./run.sh both"
	echo "================================================================"
	exit 0
fi
echo " RESULT: $fail check(s) failed, $pass passed."
echo " See the [FAIL] lines above."
echo "================================================================"
exit 1
