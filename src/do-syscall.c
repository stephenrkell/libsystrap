/*
 * Implementations of various substitution functions and helper functions
 * called during syscall emulation.
 */
#define RELF_DEFINE_STRUCTURES
#include "do-syscall.h"
#include <alloca.h>

/* Pointers to pre- and post-handling.
 * FIXME: procedurally abstract access to these, s.t. can do chaining or whatnot. */
void __attribute__((visibility("protected")))
(*__systrap_pre_handling)(struct generic_syscall *gsp);

void __attribute__((visibility("protected")))
(*__systrap_post_handling)(struct generic_syscall *gsp, long int ret);


#ifndef SYSCALL_MAX
#define SYSCALL_MAX 1023
#endif
syscall_replacement *replaced_syscalls[SYSCALL_MAX] = { NULL };

void *generic_syscall_get_ip(struct generic_syscall *gsp)
{
	return (void*) gsp->site;
}
