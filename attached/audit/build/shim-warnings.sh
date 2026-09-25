#!/usr/bin/env bash
# Re-compile the lab's own kernel files with warnings enabled.
#
# build/env.sh passes -w because scripts/basic/cc-wrapper.c (a Qualcomm
# downstream addition) turns any compiler warning anywhere in the tree into a
# build failure, and the tree is pinned to a Clang that did not produce them.
# That silence would also hide bugs in *our* code, so this script rebuilds just
# the files we authored, with warnings on and the wrapper's warnings fatal.
#
# Anything printed here is a real problem in lab code, not in pinned upstream.
#
# Usage:  ./build/shim-warnings.sh [vuln|fixed]
set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$HERE/env.sh"

VARIANT="${1:-vuln}"
export VARIANT

# Deliberately no -w.  The extra -W flags match the tree's own style; the
# suppression list covers warnings the kernel headers trigger under
# -Wextra/-Wtype-limits on GCC 13, which say nothing about our code.
WARN_FLAGS=(
  -Wall
  -Wextra
  -Wno-unused-parameter
  -Wno-sign-compare
  -Wno-missing-field-initializers
  -Wno-type-limits
  -Wno-override-init
)

# The lab's own sources, as kbuild object targets.
LAB_OBJECTS=(
  drivers/gpu/msm/kgsl_testgpu.o
)

echo "== warning check: variant=$VARIANT source=$KSRC"
echo "== objects: ${LAB_OBJECTS[*]}"

make -C "$KSRC" O="$KOUT" ARCH=arm64 CROSS_COMPILE="$CROSS_COMPILE" \
     KCFLAGS=" ${WARN_FLAGS[*]}" "${LAB_OBJECTS[@]}"

echo "== clean: no warnings in lab-authored kernel code"
