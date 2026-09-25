# Summary — how this reproduction works and why to trust it

Condensed from `audit/BUILD-REPORT.md`. Read `README.md` first for how to run it.

---

## 1. The result

| Variant | Kernel | Baseline | UAF read hits | write-through | Verdict | rc |
|---|---|---|---|---|---|---|
| vulnerable | `36f524a2` | pass | 21 / 64 | **21 / 21** | VULNERABLE | 0 |
| fixed | `44158877` | pass | 0 / 64 | 0 | NO UAF | 1 |

Across eight recorded runs: vulnerable gave 16, 21, 24, 21 hits out of 64
(25–38 %); fixed gave 0 out of 64 every time. Every run passed the identical
baseline first.

The write-through column is the important one. It is not enough for the VBO to
read freed memory — the harness additionally has the **GPU write** a known
marker through the same stale page-table entry and confirms it lands in the
reallocated page. So the primitive is bidirectional, not read-only.

---

## 2. Why an emulator, and what is real

CVE-2024-23380 needs an Adreno GPU, an SMMU, and the ability to lose a lock
race on demand. A phone does not give you the second or third.

Stock `qemu-system-aarch64` has no Adreno and no SMMU. Rather than emulate an
SMMU device and trust that its behaviour matches Qualcomm's, the lab runs the
**pinned upstream KGSL driver** against a synthetic register file, and makes the
"GPU" call **KGSL's own page-table walker**.

Concretely, everything the exploit touches is real guest kernel code:

| Component | Real? |
|---|---|
| `kgsl_vbo.c` bind/unbind and the `ranges_lock` race | **real, byte-identical to upstream** |
| `kgsl_mmu_map_child()` / `kgsl_iopgtbl_map_zero_page_to_range()` | **real, byte-identical to upstream** |
| The io-pgtable walk that dereferences the stale PTE | **real** — `arm_lpae_iova_to_phys()` from the driver itself |
| The Qualcomm io-pgtable, context banks, SMRs | **real** — arm-smmu v2 (`qcom,qsmmu-v500` + `qcom,adreno-smmu`) |
| The ioctl, memdesc, and pool paths | **real, byte-identical to upstream** |
| Ring-buffer submit, memstore retire, fence wait | **real** — a small PM4 subset, memstore timestamps written normally |
| The GPU silicon | **not real** — a software backend stands in |
| Secure world / TrustZone DCVS | **absent** — the power-scaling path is skipped |
| Host | **never involved** |

The claim is narrow and checkable: *the vulnerable code, driven by real kernel
machinery, produces a real stale page-table entry, and that entry is readable
and writable.* It is not a claim about silicon.

---

## 3. The three lab adaptations

All additive, all gated behind a device-tree property a real target never sets.
Full diffs in `audit/patches/`.

**`0001` — software GPU backend** (`drivers/gpu/msm/kgsl_testgpu.c`, new, 923
lines, plus a `Makefile` and `adreno-gpulist.h` entry). Given a GPU virtual
address, resolve the physical page the *live* SMMU shadow page table maps it to
by calling the driver's own `arm_lpae_iova_to_phys()`, then read or write it.
Also implements a small PM4 subset, memstore timestamp writes for the retire
path, cache sync, and SMMU identification-register seeding.

*Why this and not a device model:* a QEMU device would have to reimplement the
page-table walk, and any divergence would be indistinguishable from the bug
being absent. Calling the driver's own walker means the walk that dereferences
the stale PTE is the driver's own, over the same descriptors, in the same guest
memory.

Gate: `qcom,testgpu-defer-adreno-init` on `gfx3d_user`, so KGSL installs
`adreno_smmu` drvdata before arm-smmu's first automatic attach (otherwise
`qcom_adreno_smmu_init_context` NULL-derefs).

**`0002` — RAM-backed synthetic SMMU** (arm-smmu, 31 insertions). Stock `virt`
has no SMMU device, so the `qcom,qsmmu-v500` register file is backed by `no-map`
reserved RAM and gated `devm_memremap`. KGSL's own `ioremap` calls are left
untouched and pointed at the QEMU platform-bus MMIO hole. Identification
registers are seeded as ID0 `0x4e000010`, ID1 `0x20000002`, ID2 `0x1222`
(4 KiB granule, 40-bit).

Gate: `qcom,testgpu-memmap`.

**`0003` — DCVS skip** (`kgsl_pwrscale.c`, 5 insertions). No secure world
means no SCM DCVS service, so the optional devfreq governor is skipped. The
fixed clock and KGSL's generic power state machine remain live.

Gate: `qcom,testgpu-no-pwrscale`.

---

## 4. Why the two kernels are a valid differential

This is the part that decides whether the reproduction means anything.

**Same:** pinned `msm-5.10` sources, all three lab patches, the device tree, the
harness, the config fragment, the toolchain, the initramfs, the QEMU machine.

**Different:** the upstream `kgsl_vbo.c` fix, and nothing else. The complete
delta between the two snapshots is 7 lines — `kgsl_mmu_map_child()` moves from
after `mutex_unlock(&memdesc->ranges_lock)` to before
`interval_tree_insert()`:

```diff
+	ret = kgsl_mmu_map_child(memdesc->pagetable, memdesc, start,
+			&entry->memdesc, offset, last - start + 1);
+	if (ret)
+		goto error;
+
 	/* Add the new range */
 	interval_tree_insert(&range->range, &memdesc->ranges);
 	mutex_unlock(&memdesc->ranges_lock);
-	return kgsl_mmu_map_child(memdesc->pagetable, memdesc, start,
-			&entry->memdesc, offset, last - start + 1);
+	return ret;
```

The other seven protected files are **identical between the two variants** —
0 changed lines each. `verify.sh` checks that the two `Image`s are the same
size but different content, and the fixed `.text` is exactly 4,096 bytes larger,
which is the size of this change.

---

## 5. Integrity

**The eight files carrying the vulnerability** — `kgsl_vbo.c`, `kgsl_mmu.c`,
`kgsl_iommu.c`, `kgsl_sharedmem.c`, `kgsl_pool.c`, `kgsl_reclaim.c`,
`kgsl_ioctl.c`, `adreno.c` — are byte-identical to the pinned upstream tarballs
in **both** variants. Verified mechanically (`audit/build/verify-protected.sh`),
not asserted. Hashes in `audit/protected-files.sha256`.

Patches are **generated**, not hand-edited: `audit/build/refresh-patches.sh`
extracts the pristine originals from the tarball and diffs them against the
working tree, so the committed patches reproduce with no drift.

| Check | Result |
|---|---|
| Protected files, both variants | PASS — 8/8 byte-identical |
| Patch reproducibility | no drift |
| Lab code compiled with `-Wall -Wextra`, both variants | clean |
| Kernel sources | `msm-5.10` @ `36f524a2` / `44158877`, SHA-256 in `audit/build/source-manifest.txt` |

---

## 6. Honest limits

- **The race is probabilistic.** 25–38 % of attempts. The differential is a
  rate difference over 64 attempts, not a deterministic event. 0 hits on the
  vulnerable kernel means the timing window was missed, not that the bug is
  gone — see `README.md` §4.
- **No KASAN.** GPU and SMMU accesses do not pass through instrumented kernel
  code, so a sanitizer would not have caught this. The evidence is the sentinel
  data plus the `qcom-io-pgtable-arm.c:368` warning, which is the right oracle
  for this bug class.
- **The GPU is a software backend**, and its timing does not match a real Adreno
  part. The privilege of the demonstration is that the *kernel-side* machinery
  is untouched; the silicon behaviour is not being claimed.
- **No UID 0.** The arbitrary-physical read+write primitive is proven. The
  escalation to credential corruption is a separate, gated phase and has not
  been performed. Nothing in this bundle attempts it.
- **The host is out of scope.** All activity is inside the emulator. No host
  memory is mapped, no host device is opened, and there is no escape path.
