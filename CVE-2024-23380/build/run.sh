#!/usr/bin/env bash
# Boot the CVE-2024-23380 lab under stock qemu-system-aarch64.
#
# No QEMU device model is involved.  The GPU is the pinned KGSL driver with
# its "testgpu" backend compiled in; the SMMU ID aperture is reserved RAM whose
# identification registers are seeded by the lab's early initcall.  Everything
# the exploit touches -- the io-pgtable walker, the workqueue bind race, the
# retire/fence path -- is real guest kernel code executing on a real guest page
# table.
#
# The machine is stock -M virt.  The kernel is booted with -dtb so that the
# hand-written tree in dt/ is the one in force, but the CPU model, CPU count
# and RAM below must agree with what that tree declares:
#
#     dt/cve-virt.dts   4 x arm,cortex-a57, 2 GiB at 0x40000000,
#                       arm,cortex-a15-gic (GICv2), pl011 at 0x09000000
#
# Usage:  ./build/run.sh [variant] [extra qemu args...]
# Env:    QEMU_TIMEOUT   seconds before the guest is killed (default 600)
#         LAB_MEM        guest RAM (default 2G)
#         LAB_SMP        guest CPUs (default 4)
#         KGSL_LOGLEVEL  kernel printk level on the console (default 7)
set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CVE_DIR="$(cd "$HERE/.." && pwd)"

VARIANT="${1:-vuln}"
shift || true
case "$VARIANT" in
vuln|fixed) ;;
*) echo "unknown variant: $VARIANT (want vuln|fixed)" >&2; exit 2 ;;
esac

IMAGE="$CVE_DIR/out/$VARIANT/arch/arm64/boot/Image"
DTB="$CVE_DIR/dt/cve-virt.dtb"
RAMDISK="$CVE_DIR/out/ramdisk.cpio.gz"
LOG="$CVE_DIR/out/$VARIANT-run.log"

[ -f "$IMAGE" ]    || { echo "missing kernel: $IMAGE" >&2; exit 2; }
[ -f "$DTB" ]      || { echo "missing dtb:    $DTB (run build/dtb.sh)" >&2; exit 2; }
[ -f "$RAMDISK" ]  || { echo "missing ramdisk: $RAMDISK (run build/ramdisk.sh)" >&2; exit 2; }

MEM="${LAB_MEM:-2G}"
SMP="${LAB_SMP:-4}"
TIMEOUT="${QEMU_TIMEOUT:-600}"

echo "== variant: $VARIANT"
echo "== image:   $IMAGE"
echo "== dtb:     $DTB"
echo "== ramdisk: $RAMDISK"
echo "== machine: virt  cpu=cortex-a57  smp=$SMP  mem=$MEM  gic=v2"
echo "== log:     $LOG"
echo

# -display none + -serial stdio: the guest console is the only output.
# -no-reboot: a panic or a poweroff exits QEMU instead of looping.
# -monitor none: no interactive mux, so stdio is pure console and the run is
#   reproducible from a pipe.
set +e
timeout --foreground -k 10 "$TIMEOUT" \
	qemu-system-aarch64 \
		-M virt,gic-version=2 \
		-cpu cortex-a57 \
		-smp "$SMP" \
		-m "$MEM" \
		-kernel "$IMAGE" \
		-dtb "$DTB" \
		-initrd "$RAMDISK" \
		-append "console=ttyAMA0 earlycon=pl011,0x9000000 panic=-1 oops=panic loglevel=${KGSL_LOGLEVEL:-7} kgsl.debug=mask=0x1ffffffff" \
		-display none \
		-serial stdio \
		-monitor none \
		-no-reboot \
		"$@" \
	2>&1 | tee "$LOG"
rc=${PIPESTATUS[0]}
set -e

echo
echo "== qemu exit: $rc   ($([ $rc -eq 124 ] && echo 'TIMED OUT' || echo 'done'))"
echo "== log: $LOG"
exit "$rc"
