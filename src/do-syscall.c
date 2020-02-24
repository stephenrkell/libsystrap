/*
 * Implementations of various substitution functions and helper functions
 * called during syscall emulation.
 */
#define RELF_DEFINE_STRUCTURES
#include "do-syscall.h"
#include <alloca.h>

/* Dummy pre- and post-handling -- the client library 
 * will override us (we're in an archive, remember). */
void __attribute__((weak,visibility("protected")))
systrap_pre_handling(struct generic_syscall *gsp)
{
}

void __attribute__((weak,visibility("protected")))
systrap_post_handling(struct generic_syscall *gsp, long int ret)
{
}

#define RESUME resume_from_sigframe( \
		ret, \
		gsp->saved_context, \
		instr_len((unsigned char *) gsp->saved_context->uc.uc_mcontext.rip, (unsigned char *) -1) \
	)
#ifndef SYSCALL_MAX
#define SYSCALL_MAX 1023
#endif
syscall_replacement *replaced_syscalls[SYSCALL_MAX] = { NULL };

void *generic_syscall_get_ip(struct generic_syscall *gsp)
{
	return (void*) gsp->saved_context->uc.uc_mcontext.MC_REG(rip, RIP);
}
