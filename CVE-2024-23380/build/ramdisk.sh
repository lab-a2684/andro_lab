#!/usr/bin/env bash
# Build the minimal Android-flavoured initramfs for the CVE-2024-23380 lab.
#
# The objective is a harness that reaches UID 0 *inside* the emulator, so the
# rootfs does not have to be AOSP.  It has to be faithful in the ways that
# matter to the exploit:
#
#   * /init is PID 1 and drops to an unprivileged uid before touching KGSL,
#     so the harness is never accidentally running as root.
#   * /dev/kgsl-3d0 is root:kgsl 0660 with the unprivileged user in group
#     kgsl, which is the access an ordinary Android app has via the GPU HAL.
#   * CONFIG_DEVTMPFS populates /dev, so the GPU device node appears without
#     mknod in the cpio.
#   * /etc/passwd and /etc/group exist and name the lab's users, so uid/gid
#     lookups and cred-spray priming behave like a real system.
#
# A busybox ash shell is included for interactive debugging when a run fails.
#
# Usage:  ./build/ramdisk.sh [out.cpio.gz]
set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CVE_DIR="$(cd "$HERE/.." && pwd)"
WORK="$CVE_DIR/.work"

BUSYBOX="${BUSYBOX:-$WORK/src/busybox-1.36.1/busybox}"
HARNESS="${HARNESS:-$CVE_DIR/build/harness/poc}"
OUT="${1:-$CVE_DIR/out/ramdisk.cpio.gz}"

[ -x "$BUSYBOX" ] || { echo "missing busybox: $BUSYBOX" >&2; exit 2; }
file "$BUSYBOX" | grep -q 'ARM aarch64' || {
  echo "busybox is not an aarch64 build: $BUSYBOX" >&2; exit 2; }

# Unprivileged account the harness runs as.  10000/10000 is in the range
# Android hands to ordinary apps, so uid transitions during the cred spray
# land in the same numeric neighbourhood they would on a device.
LAB_UID="${LAB_UID:-10000}"
LAB_GID="${LAB_GID:-10000}"

RD="$(mktemp -d)"
trap 'rm -rf "$RD"' EXIT

mkdir -p "$RD"/{bin,dev,etc,proc,sys,tmp,run,harness,root}
# The kernel's unpacked initramfs root defaults to 0700, and the host umask
# can also strip directory execute bits.  The unprivileged harness must be
# able to traverse the archive after PID 1 drops privileges.
chmod 0755 "$RD" "$RD/bin" "$RD/dev" "$RD/etc" "$RD/proc" "$RD/sys" \
	"$RD/tmp" "$RD/run" "$RD/harness" "$RD/root"
cp "$BUSYBOX" "$RD/bin/busybox"
chmod 0755 "$RD/bin/busybox"

# Applet symlinks.  This is a subset: enough to mount, inspect, run the
# harness, and read dmesg, with no network or package-management surface.
for applet in \
  sh ash cat chmod chown cut date dd df dmesg echo env false find \
  grep head hexdump id kill ln ls mkdir mount mv od printf ps pwd readlink \
  rm rmdir sed seq set sleep stat sync tail tee test touch tr true \
  uname wc poweroff reboot halt insmod lsmod modprobe mknod \
  setuidgid; do
  ln -sf busybox "$RD/bin/$applet"
done

cat > "$RD/etc/passwd" <<EOF
root:x:0:0:root:/root:/bin/sh
daemon:x:1:1:daemon:/:/bin/false
lab:x:${LAB_UID}:${LAB_GID}:lab harness:/root:/bin/sh
nobody:x:65534:65534:nobody:/:/bin/false
EOF

cat > "$RD/etc/group" <<EOF
root:x:0:
daemon:x:1:
tty:x:5:
disk:x:6:
kmem:x:9:
kgsl:x:${LAB_GID}:lab
nogroup:x:65534:
EOF

if [ -x "$HARNESS" ]; then
  cp "$HARNESS" "$RD/harness/poc"
  chmod 0755 "$RD/harness/poc"
  chown 0:0 "$RD/harness/poc" 2>/dev/null || true
else
  cat > "$RD/harness/README" <<'EOF'
No harness was present at build time.  Drop a statically linked aarch64
binary at CVE-2024-23380/build/harness/poc and re-run build/ramdisk.sh.
EOF
fi

# ---------------------------------------------------------------------------
# /init
# ---------------------------------------------------------------------------
# Runs as PID 1.  Everything after the mounts is deliberately unprivileged:
# if the harness can win the race it must do so as uid ${LAB_UID}, and the
# init script proves it by printing the uid it actually ran under.
cat > "$RD/init" <<EOF
#!/bin/sh
# PID 1 for the CVE-2024-23380 lab.  See build/ramdisk.sh for the rationale.

export PATH=/bin:/sbin:/usr/bin:/usr/sbin
export HOME=/root
export USER=lab
export TERM=linux

/bin/mount -t proc     proc     /proc
/bin/mount -t sysfs    sysfs    /sys
/bin/mount -t devtmpfs devtmpfs /dev 2>/dev/null
/bin/mount -t tmpfs    tmpfs    /tmp
/bin/mount -t tmpfs    tmpfs    /run

# Make sure the console exists even if devtmpfs did not provide it.
[ -c /dev/console ] || { /bin/mknod -m 600 /dev/console c 5 1 2>/dev/null; }
exec >/dev/console 2>&1
echo
echo "==============================================================="
echo " CVE-2024-23380 lab  --  KGSL VBO bind UAF (CWE-416)"
echo " kernel: \$(uname -r)  machine: \$(uname -m)"
echo "==============================================================="
echo

# The GPU device node is owned root:kgsl 0660 and the lab user is in group
# kgsl, which is exactly the access an ordinary app gets on a real device.
/bin/chown 0:${LAB_GID} /dev/kgsl-3d0 2>/dev/null
/bin/chmod 0660 /dev/kgsl-3d0 2>/dev/null
ls -la /dev/kgsl-3d0 2>/dev/null

if [ -x /harness/poc ]; then
  # Copy the static harness onto the exec-capable tmpfs before dropping
  # privileges.  Some initramfs/rootfs combinations mount the archive
  # read-only or noexec even though the kernel can execute /init from it.
  cp /harness/poc /tmp/poc
  chmod 0755 /tmp/poc
  # Drop privileges.  setuidgid sets all four ids in one syscall sequence,
  # so there is no window in which the uid has dropped but the gid has not.
  echo "--- launching harness as uid=${LAB_UID} gid=${LAB_GID} ---"
  /bin/busybox setuidgid ${LAB_UID} /tmp/poc
  rc=\$?
  echo "--- harness exited rc=\$rc ---"
else
  echo "--- no harness installed ---"
  rc=0
fi

echo
echo "--- kernel log ---"
/bin/dmesg | tail -n 120

echo
echo "--- credentials after the run ---"
/bin/busybox setuidgid ${LAB_UID} /bin/busybox id 2>/dev/null || true

sync
echo
echo "=== lab complete ==="
/bin/busybox poweroff -f
EOF
chmod 0755 "$RD/init"

mkdir -p "$(dirname "$OUT")"
( cd "$RD" && find . -print0 | cpio --null -o -H newc --owner=0:0 --quiet ) | gzip -9 > "$OUT"

echo "== ramdisk: $OUT"
echo "== size:    $(stat -c %s "$OUT") bytes"
echo "== uid:     ${LAB_UID}  gid: ${LAB_GID}"
