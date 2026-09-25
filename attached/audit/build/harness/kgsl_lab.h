/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * kgsl_lab.h - user-space helpers for the CVE-2024-23380 KGSL lab.
 *
 * Everything the harness knows about the KGSL ABI comes from the *pinned
 * kernel's* UAPI header, compiled in with -I against the snapshot.  Copying
 * struct definitions out of a public PoC, as a first draft might, risks a
 * silent layout or ioctl-number mismatch against the tree we are actually
 * testing; including the real header removes that entire class of bug.
 *
 * Only the PM4 encoder lives here -- that is a property of the hardware
 * wire format, not of the driver ABI.
 */
#ifndef KGSL_LAB_H
#define KGSL_LAB_H

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

/* The pinned tree's UAPI.  -I is set by build/harness.sh.
 *
 * msm_kgsl.h is written against the kernel's own linux/types.h and uses two
 * decorations that do not exist in user space.  __user is the kernel's
 * userspace-access annotation and expands to nothing outside the kernel; the
 * same is true here.  __kernel_size_t is the kernel's size_t, which is
 * unsigned long on arm64.  Defining them here -- rather than shadowing the
 * whole include/uapi tree -- lets msm_kgsl.h's own <linux/types.h> resolve
 * to the system header, which is the one that actually works for a libc
 * program.
 */
#ifndef __user
#define __user
#endif
#ifndef __kernel_size_t
#define __kernel_size_t unsigned long
#endif

#include <linux/msm_kgsl.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096u
#endif

#define LAB_KGSL_DEV "/dev/kgsl-3d0"

#define lab_err(fmt, ...)                                                   \
	do {                                                                  \
		fprintf(stderr, "[!] " fmt "\n", ##__VA_ARGS__);             \
		exit(1);                                                     \
	} while (0)

/* Run x, aborting the lab if it returns -1 (errno is preserved). */
#define LAB_CHK(x)                                                           \
	do {                                                                  \
		if ((x) == -1)                                                \
			lab_err("%s: %s", #x, strerror(errno));              \
	} while (0)

/* Run an ioctl, printing the failing errno if it returns -1. */
#define LAB_IOCTL(fd, req, arg)                                              \
	do {                                                                  \
		if (ioctl((fd), (req), (arg)) == -1)                          \
			lab_err("ioctl %s (%s): %s", #req, #arg,             \
				strerror(errno));                             \
	} while (0)

static inline void hexdump(const void *_data, size_t byte_count)
{
	const unsigned char *bytes = _data;

	printf("hexdump(%p, 0x%zx)\n", _data, byte_count);
	for (size_t off = 0; off < byte_count; off += 16) {
		size_t line_bytes = (byte_count - off > 16) ?
			16 : (byte_count - off);
		char line[128];
		size_t w = (size_t)snprintf(line, sizeof(line), "%08zx  ", off);

		for (size_t i = 0; i < 16; i++) {
			if (i >= line_bytes)
				w += (size_t)snprintf(line + w,
						      sizeof(line) - w, "   ");
			else
				w += (size_t)snprintf(line + w,
						      sizeof(line) - w,
						      "%02hhx ", bytes[off + i]);
		}
		w += (size_t)snprintf(line + w, sizeof(line) - w, " |");
		for (size_t i = 0; i < line_bytes; i++) {
			unsigned char c = bytes[off + i];
			line[w++] = (c == ' ' || (c >= 0x20 && c < 0x7f)) ?
				(char)c : '.';
		}
		snprintf(line + w, sizeof(line) - w, "|\n");
		fputs(line, stdout);
	}
}

/* ---------------------------------------------------------------------- */
/* KGSL ioctl wrappers                                                    */
/* ---------------------------------------------------------------------- */

static inline uint64_t kgsl_gpuobj_alloc(int fd, size_t size, uint64_t flags)
{
	struct kgsl_gpuobj_alloc arg = {
		.size = size, .flags = flags, .va_len = size,
	};

	LAB_IOCTL(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &arg);
	return arg.id;
}

static inline uint64_t kgsl_gpumem_alloc(int fd, size_t size, unsigned int flags)
{
	struct kgsl_gpumem_alloc kga = { .size = size, .flags = flags };

	LAB_IOCTL(fd, IOCTL_KGSL_GPUMEM_ALLOC, &kga);
	return kga.gpuaddr;
}

static inline void kgsl_gpumem_free(int fd, unsigned int id)
{
	struct kgsl_gpumem_free_id arg = { .id = id };

	LAB_IOCTL(fd, IOCTL_KGSL_GPUMEM_FREE_ID, &arg);
}

static inline uint64_t kgsl_gpuobj_gpuaddr(int fd, unsigned int id)
{
	struct kgsl_gpuobj_info arg = { .id = id };

	LAB_IOCTL(fd, IOCTL_KGSL_GPUOBJ_INFO, &arg);
	return arg.gpuaddr;
}

static inline uint32_t kgsl_drawctxt_create(int fd, unsigned int flags)
{
	struct kgsl_drawctxt_create arg = {
		.flags = flags | KGSL_CONTEXT_PREAMBLE |
			 KGSL_CONTEXT_NO_GMEM_ALLOC,
	};

	LAB_IOCTL(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &arg);
	return arg.drawctxt_id;
}

/* ---------------------------------------------------------------------- */
/* PM4 encoder                                                            */
/* ---------------------------------------------------------------------- */
/*
 * Modern Adreno PM4: the header is the *high* dword of the packet, with
 * [31:28] = packet type, [26:16] = opcode, [14:0] = payload count in
 * dwords.  Bits 15 and 23 are the odd-parity bits for the count and the
 * opcode respectively.  Parity is checked by hardware but we compute it
 * properly so the packets are well-formed rather than merely accepted.
 */

#define PM4_TYPE7_PKT (7u << 28)

#define CP_NOP                 0x10
#define CP_WAIT_MEM_WRITES     0x12
#define CP_WAIT_FOR_ME         0x13
#define CP_EVENT_WRITE         0x46
#define CP_WAIT_FOR_IDLE       0x26
#define CP_MEM_WRITE           0x3d
#define CP_REG_TO_MEM          0x3e
#define CP_MEM_TO_MEM          0x73
#define CP_MEMCPY              0x75

static inline uint32_t upper_32_bits(uint64_t n) { return (uint32_t)(n >> 32); }
static inline uint32_t lower_32_bits(uint64_t n) { return (uint32_t)n; }

static inline uint32_t pm4_odd_parity(uint32_t val)
{
	return (0x9669u >> (0xf & (val ^ (val >> 4) ^ (val >> 8) ^ (val >> 12) ^
				     (val >> 16) ^ (val >> 20) ^ (val >> 24) ^
				     (val >> 28)))) & 1;
}

static inline uint32_t cp_type7_packet(uint32_t opcode, uint32_t cnt)
{
	return PM4_TYPE7_PKT | (cnt & 0x7fff) |
	       (pm4_odd_parity(cnt) << 15) |
	       ((opcode & 0x7ff) << 16) |
	       (pm4_odd_parity(opcode) << 23);
}

static inline uint32_t *emit_gpuaddr(uint32_t *cmds, uint64_t addr)
{
	*cmds++ = lower_32_bits(addr);
	*cmds++ = upper_32_bits(addr);
	return cmds;
}

/*
 * One CP_MEMCPY: count (in dwords), src, dst.  len must be a multiple of 4
 * and no larger than what one packet's 15-bit count field can express.
 */
static inline uint32_t *emit_gpu_memcpy(uint32_t *cmds, uint64_t dst,
					uint64_t src, size_t len)
{
	if (len == 0)
		return cmds;
	if (len % 4 || len > 0x7fff * 4)
		lab_err("bad CP_MEMCPY length %zu", len);

	*cmds++ = cp_type7_packet(CP_MEMCPY, 5);
	*cmds++ = (uint32_t)(len / 4);
	cmds = emit_gpuaddr(cmds, src);
	cmds = emit_gpuaddr(cmds, dst);
	return cmds;
}

/*
 * One CP_MEM_WRITE: dst, then the data inline.  Hardware accepts up to
 * 0x7fff dwords total, so 0x7ffd bytes of payload per packet.
 */
static inline uint32_t *emit_gpu_memwrite(uint32_t *cmds, uint64_t dst,
					  const uint32_t *src, size_t len)
{
	if (len == 0)
		return cmds;
	if (len % 4 || len > 0x7ffd)
		lab_err("bad CP_MEM_WRITE length %zu", len);

	*cmds++ = cp_type7_packet(CP_MEM_WRITE, 2 + (uint32_t)(len / 4));
	cmds = emit_gpuaddr(cmds, dst);
	for (size_t i = 0; i < len / 4; i++)
		*cmds++ = src[i];
	return cmds;
}

/* Trailing ordering packets: make the preceding accesses observable. */
static inline uint32_t *emit_fence(uint32_t *cmds)
{
	*cmds++ = cp_type7_packet(CP_WAIT_MEM_WRITES, 0);
	*cmds++ = cp_type7_packet(CP_WAIT_FOR_IDLE, 0);
	return cmds;
}

/* ---------------------------------------------------------------------- */
/* Command submission                                                     */
/* ---------------------------------------------------------------------- */

/*
 * Submit one indirect buffer and block until the driver has retired it.
 *
 * The fence is not decoration: it is the proof that the whole generic retire
 * path ran.  The testgpu backend signals completion by writing timestamps
 * into the global memstore, after which adreno_dispatcher_retire_drawqueue()
 * retires the drawobj and fires the event group this fence is waiting on.
 * If the completion signalling were wrong, this poll would hang and the lab
 * would say so rather than silently reporting stale payload bytes.
 */
static inline void kgsl_gpu_command(int fd, uint32_t ctx_id,
				    uint64_t gpuaddr, unsigned int size)
{
	struct kgsl_command_object cmd = {
		.gpuaddr = gpuaddr,
		.size = size,
		.flags = KGSL_CMDLIST_IB,
	};
	struct kgsl_gpu_command req = {
		.flags = KGSL_CONTEXT_SUBMIT_IB_LIST,
		.cmdlist = (uint64_t)(uintptr_t)&cmd,
		.cmdsize = sizeof(cmd),
		.numcmds = 1,
		.context_id = ctx_id,
	};
	struct kgsl_timestamp_event_fence tef = { .fence_fd = -1 };
	struct kgsl_timestamp_event tse;

	LAB_IOCTL(fd, IOCTL_KGSL_GPU_COMMAND, &req);
	/* The submit ioctl writes the real retired timestamp back to req. */
	tse = (struct kgsl_timestamp_event) {
		.type = KGSL_TIMESTAMP_EVENT_FENCE,
		.timestamp = req.timestamp,
		.context_id = ctx_id,
		.priv = &tef,
		.len = sizeof(tef),
	};
	LAB_IOCTL(fd, IOCTL_KGSL_TIMESTAMP_EVENT, &tse);
	if (tef.fence_fd == -1)
		lab_err("no fence returned for timestamp %u", req.timestamp);

	struct pollfd pfd = { .fd = tef.fence_fd, .events = POLLIN };

	LAB_CHK(poll(&pfd, 1, -1));
	close(tef.fence_fd);
}

#endif /* KGSL_LAB_H */
