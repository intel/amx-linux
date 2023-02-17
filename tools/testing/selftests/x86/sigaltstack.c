// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <setjmp.h>

#include "helpers.h"

/* sigaltstack()-enforced minimum stack */
#define ENFORCED_MINSIGSTKSZ	2048

#ifndef AT_MINSIGSTKSZ
#  define AT_MINSIGSTKSZ	51
#endif

static int nerrs;

static bool sigalrm_expected;

static unsigned long at_minstack_size;

static jmp_buf jmpbuf;

static void sigsegv(int sig, siginfo_t *info, void *ctx_void)
{
	if (sigalrm_expected) {
		printf("[FAIL]\tWrong signal delivered: SIGSEGV (expected SIGALRM).");
		nerrs++;
	} else {
		printf("[OK]\tSIGSEGV signal delivered.\n");
	}

	siglongjmp(jmpbuf, 1);
}

static void sigalrm(int sig, siginfo_t *info, void *ctx_void)
{
	if (!sigalrm_expected) {
		printf("[FAIL]\tWrong signal delivered: SIGALRM (expected SIGSEGV).");
		nerrs++;
	} else {
		printf("[OK]\tSIGALRM signal delivered.\n");
	}
}

static void test_sigaltstack(stack_t *stack)
{
	if (sigaltstack(stack, NULL)) {
		/*
		 * The kernel may return ENOMEM when the altstack size
		 * is insufficient. Skip the test in this case.
		 */
		if (errno == ENOMEM && stack->ss_size < at_minstack_size) {
			printf("[SKIP]\tThe running kernel disallows an insufficient size.\n");
			return;
		}

		err(1, "sigaltstack()");
	}

	sigalrm_expected = (stack->ss_size > at_minstack_size) ? true : false;

	sethandler(SIGSEGV, sigsegv, 0);
	sethandler(SIGALRM, sigalrm, SA_ONSTACK);

	if (!sigsetjmp(jmpbuf, 1)) {
		printf("[RUN]\tTest an alternate signal stack of %ssufficient size.\n",
		       sigalrm_expected ? "" : "in");
		printf("\tRaise SIGALRM. %s is expected to be delivered.\n",
		       sigalrm_expected ? "It" : "SIGSEGV");
		raise(SIGALRM);
	}

	clearhandler(SIGALRM);
	clearhandler(SIGSEGV);
}

int main(void)
{
	unsigned long enough_size;
	stack_t stack = { };

	at_minstack_size = getauxval(AT_MINSIGSTKSZ);

	if (init_sigaltstack(&stack) != 0)
		err(1, "sigaltstack allocation failed.");
	enough_size = stack.ss_size;

	if ((ENFORCED_MINSIGSTKSZ + 1) < at_minstack_size) {
		stack.ss_size = ENFORCED_MINSIGSTKSZ + 1;
		test_sigaltstack(&stack);
	}

	stack.ss_size = enough_size;
	test_sigaltstack(&stack);

	cleanup_sigaltstack(&stack);

	return nerrs == 0 ? 0 : 1;
}
