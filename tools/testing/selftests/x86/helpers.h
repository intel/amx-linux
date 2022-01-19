// SPDX-License-Identifier: GPL-2.0-only
#ifndef __SELFTESTS_X86_HELPERS_H
#define __SELFTESTS_X86_HELPERS_H

#include <signal.h>
#include <asm/processor-flags.h>

void sethandler(int sig, void (*handler)(int, siginfo_t *, void *),
		int flags);

void clearhandler(int sig);

static inline unsigned long get_eflags(void)
{
#ifdef __x86_64__
	return __builtin_ia32_readeflags_u64();
#else
	return __builtin_ia32_readeflags_u32();
#endif
}

static inline void set_eflags(unsigned long eflags)
{
#ifdef __x86_64__
	__builtin_ia32_writeeflags_u64(eflags);
#else
	__builtin_ia32_writeeflags_u32(eflags);
#endif
}

#endif /* __SELFTESTS_X86_HELPERS_H */
