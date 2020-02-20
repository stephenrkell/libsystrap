/*
 * Implementations of various substitution functions and helper functions
 * called during syscall emulation.
 */
#define RELF_DEFINE_STRUCTURES
#include "do-syscall.h"
#include "syscall-names.h"
#include <alloca.h>

/* Dummy pre- and post-handling -- the client library 
 * will override us (we're in an archive, remember). */
void __attribute__((visibility("protected")))
systrap_pre_handling(struct generic_syscall *gsp)
{
}

void __attribute__((visibility("protected")))
systrap_post_handling(struct generic_syscall *gsp, long int ret)
{
}

#define RESUME resume_from_sigframe( \
		ret, \
		gsp->saved_context, \
		instr_len((unsigned char *) gsp->saved_context->uc.uc_mcontext.rip, (unsigned char *) -1) \
	)

/*
#define DECL_SYSCALL(x) [SYS_ ## x ] = do_ ## x ,
syscall_replacement *replaced_syscalls[SYSCALL_MAX] = {
	DECL_SYSCALL(read)
	DECL_SYSCALL(write)
	DECL_SYSCALL(open)
	DECL_SYSCALL(getpid)
	DECL_SYSCALL(exit)
	DECL_SYSCALL(time)
};
#undef DECL_SYSCALL
*/
syscall_replacement *replaced_syscalls[SYSCALL_MAX] = { NULL };
