# CVE-2024-23380 — KGSL VBO bind UAF reproduction bundle

Self-contained, prebuilt, guest-only reproduction of **CVE-2024-23380**
(CWE-416, use-after-free) in the Qualcomm KGSL (Adreno) GPU driver.

Everything needed to run is already compiled. **You do not need a compiler, a
kernel source tree, busybox, root, or KVM.**

---

## 1. What you need

| | |
|---|---|
| Required | `qemu-system-aarch64` (6.0 or newer), `bash`, coreutils |
| Optional | `gzip` + `cpio` (lets `verify.sh` inspect the initramfs) |
| Not needed | compiler, kernel sources, `/dev/kvm`, root |

```sh
# Debian / Ubuntu
sudo apt-get install qemu-system-arm
# Fedora
sudo dnf install qemu-system-aarch64
# Arch
sudo pacman -S qemu-system-arm
```

The guest runs under **TCG** (CPU emulation), on purpose: the thing under test
is the kernel's page-table and locking logic, not CPU performance.

---

## 2. Run it

```sh
./verify.sh          # check bundle integrity + host readiness
./run.sh both        # run the vulnerable/fixed differential
```

`./run.sh` also takes `vuln` or `fixed` on its own. Each run takes roughly
1–3 minutes depending on the host. Full guest console output lands in
`logs/<variant>-<timestamp>.log`.

---

## 3. What you should see

```
 SUMMARY
================================================================
 VARIANT  harness rc  UAF hits     write-through   VERDICT
 vuln     0            21           21              VULNERABLE
 fixed    1            0            0               NO UAF
```

`vuln` exits **0**, `fixed` exits **1**. On success `./run.sh` prints
`Result: as documented.` and itself exits 0.

For reference, this is what the shipped `reference-logs/` contain — 21 of 64
attempts hit on the vulnerable kernel, and **every** read hit was also a
write-through hit.

### The oracle, in plain terms

Each of the 64 attempts does this:

1. Allocate a VBO and a same-sized **child** buffer; fill the child with `0x41`.
2. Race a GPU **bind** of the child against an **unbind** of the same range.
3. Free the child.
4. Allocate a same-sized **placeholder**; fill it with `0x44`.
5. Read the VBO through the live GPU page table.

* If the VBO reads back **`0x44444444`** — the VBO still points at the child's
  physical pages, which the allocator has since handed to the placeholder.
  That is the use-after-free.
* On every such hit the harness then has the **GPU write** `0xcafebabe` to the
  same VBO address and checks the placeholder's user mapping. If the write
  shows up there, the stale page-table entry is a two-way
  arbitrary-physical-page read **and write** primitive.

The vulnerable kernel also prints an in-kernel confirmation during the race:

```
arm_lpae_init_pte ... qcom-io-pgtable-arm.c:368 ... (-EEXIST)
```

That is the unbind's zero-page remap colliding with the PTE the bind already
installed — `kgsl_memdesc_remove_range()` ignores the error, so the stale PTE
survives. The fixed kernel prints no such warning.

### The underlying bug

`kgsl_memdesc_add_range()` in `drivers/gpu/msm/kgsl_vbo.c` inserts the
interval-tree range and **releases `ranges_lock`** *before* calling
`kgsl_mmu_map_child()`. An unbind landing in that window removes the range and
frees the child, and the bind then installs a PTE for memory that no longer
belongs to the memdesc. The upstream fix moves `kgsl_mmu_map_child()` inside
the lock, before the interval-tree insert.

---

## 4. If the vulnerable kernel reports 0 hits

**That is not a clean bill of health — it is a lost race.** The bug is
timing-dependent, and the hit rate is roughly 25–38 % of attempts. A slower or
faster host, a busier machine, or a different CPU count all move that number.

The fix is to give the race a wider window, which means rebuilding the
initramfs. That is a build step and is deliberately **not** part of this
bundle. The sources and build scripts are in `audit/`, and the full procedure
is in `audit/BUILD-REPORT.md` §15. The knobs are:

| Variable | Default | Effect |
|---|---|---|
| `LAB_ATTEMPTS` | 64 | how many races to run |
| `LAB_START_DELAY_US` | 1000 | delay between the bind and the unbind |
| `LAB_PLACEHOLDERS` | 8 | how many reallocations to try per race |
| `LAB_SETTLE_MS` | 300 | pause before probing the VBO |

A vulnerable kernel that reports 0 hits in 64 attempts, on a host where the
shipped reference log got 21, is worth investigating. But the only fully
convincing negative result is the **fixed** kernel — which is why the bundle
ships both.

---

## 5. What this bundle does **not** do

Stated plainly, because a working UAF primitive deserves an accurate label:

- **It does not obtain UID 0.** This is a *detection and proof-of-primitive*
  PoC. It demonstrates the use-after-free and that the stale page-table entry
  is readable and writable. Privilege escalation to root is a separate phase
  that has not been started.
- **It never touches the host.** The harness runs inside the emulated guest
  only. Nothing in this bundle maps host memory, opens a host device, or
  provides a path off the virtual machine.
- **It is not a weaponised exploit.** There is no root payload, no
  persistence, and no targeting logic. `run.sh` boots a local emulator.
- **The GPU is not silicon.** The lab uses an additive software GPU backend
  (see `SUMMARY.md` §3) that walks KGSL's *own* page-table walker. The race,
  the page-table fault, and the memstore/fence retire path are genuine kernel
  code; the hardware underneath is not.

If you need this for defensive work — triage, a regression test, a fix
verifier — it is scoped for exactly that.

---

## 6. Layout

```
kernel/Image-vuln            32,836,096   vulnerable kernel (msm-5.10 @ 36f524a2)
kernel/Image-fixed           32,836,096   fixed      kernel (msm-5.10 @ 44158877)
dtb/cve-virt.dtb                  3,716   hand-written arm64 virt device tree
initramfs/ramdisk.cpio.gz     1,529,795   busybox + the static harness inside
run.sh                                  standalone runner
verify.sh                              integrity + host checks
MANIFEST.sha256                       SHA-256 of every file here
README.md                              this file
SUMMARY.md                             provenance, method, results, and why it is trustworthy
reference-logs/                       two known-good runs to diff yours against
audit/                                small text: everything needed to audit the build
logs/                                 your runs land here
```

### The `audit/` folder

Read-only reference material — nothing in it is executed by `run.sh`.

| Path | What it is |
|---|---|
| `patches/0001-…` | the software GPU backend (new file, 923 lines) |
| `patches/0002-…` | RAM-backed synthetic SMMU for arm-smmu |
| `patches/0003-…` | DCVS/TrustZone power-scaling skip (5 lines) |
| `dt/cve-virt.dts` | the device tree, readable |
| `config/frag-cve.config` | the kernel config fragment, with its rationale inline |
| `build/*.sh` | the build/run scripts, with their reasoning in comments |
| `build/harness/poc.c` | the harness source |
| `build/harness/kgsl_lab.h` | UAPI wrappers, PM4 encoder |
| `protected-files.sha256` | hashes of the 8 KGSL files that carry the bug |
| `BUILD-REPORT.md` | the full 806-line build report |

All three patches are **additive or gated behind a DT property that a real
target never sets**. The eight files containing the vulnerability
(`kgsl_vbo.c`, `kgsl_mmu.c`, `kgsl_iommu.c`, `kgsl_sharedmem.c`,
`kgsl_pool.c`, `kgsl_reclaim.c`, `kgsl_ioctl.c`, `adreno.c`) are
byte-identical to the pinned upstream tarballs in both builds.

---

## 7. Integrity: what is and is not provable here

`MANIFEST.sha256` plus `verify.sh` prove that **this bundle is byte-for-byte the
one that was produced and shipped**, and that nothing was corrupted in transit.
They do **not** re-derive the kernels from source.

To confirm the sources themselves are upstream's, you need the two pinned
Qualcomm tarballs (~191 MB each) plus `gdb`, which are not shipped here. What
*is* shipped is `audit/protected-files.sha256` — the hashes those eight files
had in the pinned tarball. If you obtain the sources, one command settles it:

```sh
sha256sum -c audit/protected-files.sha256     # from the extracted kernel root
```

The build's own check, `audit/build/verify-protected.sh`, performs exactly this
and reports `PASS: all 8 protected files match the pinned tarball byte for byte.`
It was run against both variants.

---

## 8. Provenance

| | |
|---|---|
| Vulnerable kernel | `msm-5.10` @ `36f524a278d3c2e72b426e7385814366a626b936` |
| Fixed kernel | `msm-5.10` @ `44158877bd0b2fbf65b62ef15815dc43c0dcf429` |
| Upstream | `git.codelinaro.org/clo/la/kernel/msm-5.10.git` |
| Reference PoC consulted | `github.com/m1zole/adreno-1day` @ `fcd41226` |
| Built with | `aarch64-linux-gnu-gcc` 13.3.0, Ubuntu 24.04.5 x86_64 host |
| Emulator used for the reference runs | QEMU 8.2.2 |

The two `Image`s are the **same size and different content**. The only
kernel-side difference between them is the upstream `kgsl_vbo.c` fix — same
sources, same patches, same device tree, same harness. `verify.sh` checks
exactly that property, and the fixed `.text` is 4,096 bytes larger than the
vulnerable one, which is the size of the change.

---

## 9. Troubleshooting

| Symptom | Cause |
|---|---|
| `qemu-system-aarch64 not found` | install QEMU for aarch64; see §1 |
| Guest never prints the banner | wrong QEMU/DT pairing — run `./verify.sh`, it tests the exact machine line |
| `QEMU terminated` immediately | CPU unsupported by that QEMU build; try a newer QEMU |
| 0 UAF hits on `vuln` | lost race, not a clean result — see §4 |
| `harness exited rc=?` | the guest panicked before finishing; read the log, grep for `Unable to handle` or `BUG` |
| `out of memory` on a small host | the guest wants 2 GiB; raise `LAB_MEM` only if you also change the device tree |

`logs/` accumulates one file per run. The kernel prints a lot; the oracle lines
are the ones beginning `[+]`, and the summary block at the end has the verdict.

---

## 10. Scope and authorisation

This is a research reproduction of a **public, already-patched CVE**, built to
run entirely inside a local emulator. Use it for triage, regression testing,
and fix verification. It is not intended for use against devices you do not own
or are not authorised to test.
