// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <string.h>
#include <err.h>

#include <sys/auxv.h>
#include <sys/mman.h>

#include "helpers.h"

#ifndef AT_MINSIGSTKSZ
#  define AT_MINSIGSTKSZ	51
#endif

#include "helpers.h"

void sethandler(int sig, void (*handler)(int, siginfo_t *, void *),
		int flags)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = handler;
	sa.sa_flags = SA_SIGINFO | flags;
	sigemptyset(&sa.sa_mask);
	if (sigaction(sig, &sa, 0))
		err(1, "sigaction");
}

void clearhandler(int sig)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_DFL;
	sigemptyset(&sa.sa_mask);
	if (sigaction(sig, &sa, 0))
		err(1, "sigaction");
}

#define ALTSTKSZ	8096

static unsigned long get_sigaltstacksz(void)
{
	return getauxval(AT_MINSIGSTKSZ) + ALTSTKSZ;
}

/**
 * init_sigalstack -- allocate an altstack without registration
 * @stack:	stack_t pointer
 * Returns:	0 if successful; otherwise, nonzero
 *
 * Unless testing with different sizes, setup_sigaltstack() should be
 * enough to provide a ready-to-use stack
 */
int init_sigaltstack(stack_t *stack)
{
	if (!stack)
		return -1;

	if (stack->ss_size > 0 && stack->ss_sp > 0)
		return 0;

	stack->ss_size = get_sigaltstacksz();

	stack->ss_sp = mmap(NULL, stack->ss_size, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	if (stack->ss_sp == MAP_FAILED)
		return -1;

	return 0;
}

/**
 * setup_sigaltstack -- allocate and register an altstack
 * @stack:	stack_t pointer
 * Returns:	0 if successful; otherwise, nonzero
 */
int setup_sigaltstack(stack_t *stack)
{
	int rc;

	rc = init_sigaltstack(stack);
	if (rc)
		return -1;

	return sigaltstack(stack, NULL);
}

/**
 * cleanup_sigaltstack -- unregister and free an altstack
 * @stack:	stack_t pointer
 * Returns:	None
 */
void cleanup_sigaltstack(stack_t *stack)
{
	size_t size;
	void *sp;

	if (!stack)
		return;

	size = stack->ss_size;
	sp = stack->ss_sp;

	stack->ss_flags = SS_DISABLE;
	sigaltstack(stack, NULL);

	munmap(sp, size);
}
