// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <err.h>
#include <elf.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <x86intrin.h>

#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/uio.h>

#include "../kselftest.h" /* For __cpuid_count() */

#define LEGACY_STATE_SIZE	24
#define MXCSR_SIZE		8
#define STSTATE_SIZE		8*16
#define XMM_SIZE		16*16
#define PADDING_SIZE		96
#define XSAVE_HDR_SIZE		64

struct xsave_buffer {
	uint8_t		legacy_state[LEGACY_STATE_SIZE];
	uint8_t		mxcsr[MXCSR_SIZE];
	uint8_t		st_state[STSTATE_SIZE];
	uint8_t		xmm_state[XMM_SIZE];
	uint8_t		padding[PADDING_SIZE];
	uint8_t		header[XSAVE_HDR_SIZE];
	uint8_t		extended[0];
};

#ifdef __x86_64__
#define REX_PREFIX	"0x48, "
#else
#define REX_PREFIX
#endif

#define XSAVE		".byte " REX_PREFIX "0x0f,0xae,0x27"
#define XRSTOR		".byte " REX_PREFIX "0x0f,0xae,0x2f"

static inline uint64_t xgetbv(uint32_t index)
{
	uint32_t eax, edx;

	asm volatile("xgetbv"
		     : "=a" (eax), "=d" (edx)
		     : "c" (index));
	return eax + ((uint64_t)edx << 32);
}

static inline void xsave(struct xsave_buffer *xbuf, uint64_t rfbm)
{
	uint32_t rfbm_lo = rfbm;
	uint32_t rfbm_hi = rfbm >> 32;

	asm volatile(XSAVE :: "D" (xbuf), "a" (rfbm_lo), "d" (rfbm_hi) : "memory");
}

static inline void xrstor(struct xsave_buffer *xbuf, uint64_t rfbm)
{
	uint32_t rfbm_lo = rfbm;
	uint32_t rfbm_hi = rfbm >> 32;

	asm volatile(XRSTOR :: "D" (xbuf), "a" (rfbm_lo), "d" (rfbm_hi));
}

static inline void clear_xstate_header(struct xsave_buffer *xbuf)
{
	memset(&xbuf->header, 0, sizeof(xbuf->header));
}

static inline uint32_t get_mxcsr(struct xsave_buffer *xbuf)
{
	return *((uint32_t *)xbuf->mxcsr);
}

static inline void set_mxcsr(struct xsave_buffer *xbuf, uint32_t val)
{
	*((uint32_t *)xbuf->mxcsr) = val;
}

#define XFEATURE_MASK_SSE		0x2
#define XFEATURE_MASK_YMM		0x4

#define CPUID_LEAF1_ECX_XSAVE_MASK	(1 << 26)
#define CPUID_LEAF1_ECX_OSXSAVE_MASK	(1 << 27)
#define CPUID_LEAF_XSTATE		0xd
#define CPUID_SUBLEAF_XSTATE_USER	0x0
#define CPUID_SUBLEAF_XSTATE_EXT	0x1

static bool xsave_availability(void)
{
	uint32_t eax, ebx, ecx, edx;

	__cpuid_count(1, 0, eax, ebx, ecx, edx);
	if (!(ecx & CPUID_LEAF1_ECX_XSAVE_MASK))
		return false;
	if (!(ecx & CPUID_LEAF1_ECX_OSXSAVE_MASK))
		return false;
	return true;
}

static uint32_t get_xbuf_size(void)
{
	uint32_t eax, ebx, ecx, edx;

	__cpuid_count(CPUID_LEAF_XSTATE, CPUID_SUBLEAF_XSTATE_USER,
		      eax, ebx, ecx, edx);
	return ebx;
}

static void ptrace_get(pid_t pid, struct iovec *iov)
{
	memset(iov->iov_base, 0, iov->iov_len);

	if (ptrace(PTRACE_GETREGSET, pid, (uint32_t)NT_X86_XSTATE, iov))
		err(1, "TRACE_GETREGSET");
}

static void ptrace_set(pid_t pid, struct iovec *iov)
{
	if (ptrace(PTRACE_SETREGSET, pid, (uint32_t)NT_X86_XSTATE, iov))
		err(1, "TRACE_SETREGSET");
}

int main(void)
{
	struct xsave_buffer *xbuf;
	uint32_t xbuf_size;
	struct iovec iov;
	uint32_t mxcsr;
	pid_t child;
	int status;

	if (!xsave_availability())
		printf("[SKIP]\tSkip as XSAVE not available.\n");

	xbuf_size = get_xbuf_size();
	if (!xbuf_size)
		printf("[SKIP]\tSkip as XSAVE not available.\n");

	if (!(xgetbv(0) & (XFEATURE_MASK_SSE | XFEATURE_MASK_YMM)))
		printf("[SKIP]\tSkip as SSE state not available.\n");

	xbuf = aligned_alloc(64, xbuf_size);
	if (!xbuf)
		err(1, "aligned_alloc()");

	iov.iov_base = xbuf;
	iov.iov_len = xbuf_size;

	child = fork();
	if (child < 0) {
		err(1, "fork()");
	} else if (!child) {
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL))
			err(1, "PTRACE_TRACEME");

		raise(SIGTRAP);
		_exit(0);
	}

	wait(&status);

	if (WSTOPSIG(status) != SIGTRAP)
		err(1, "raise(SIGTRAP)");

	printf("[RUN]\tTest the MXCSR state write via ptrace().\n");

	/* Set a benign value */
	set_mxcsr(xbuf, 0xabc);
	/* The MXCSR state should be loaded regardless of XSTATE_BV */
	clear_xstate_header(xbuf);

	/* Write the MXCSR state both locally and remotely. */
	xrstor(xbuf, XFEATURE_MASK_SSE);
	ptrace_set(child, &iov);

	/* Read the MXCSR state back for both */
	xsave(xbuf, XFEATURE_MASK_SSE);
	mxcsr = get_mxcsr(xbuf);
	ptrace_get(child, &iov);

	/* Cross-check with each other */
	if (mxcsr == get_mxcsr(xbuf))
		printf("[OK]\tThe written state was read back correctly.\n");
	else
		printf("[FAIL]\tThe write (or read) was incorrect.\n");

	ptrace(PTRACE_DETACH, child, NULL, NULL);
	wait(&status);
	if (!WIFEXITED(status) || WEXITSTATUS(status))
		err(1, "PTRACE_DETACH");

	free(xbuf);
}
