#define RELF_DEFINE_STRUCTURES
#include "raw-syscalls-impl.h"
#ifdef __linux__
#define sigset_t __asm_sigset_t
#endif
#include <sys/mman.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include "systrap_private.h"
#include "do-syscall.h"

/* I wanted to put this in sigill.c, because it has to do something that
 * mirrors what the signal handler there has to do. However, the following... */
#pragma GCC optimize "-fomit-frame-pointer"
__attribute__((optimize("omit-frame-pointer")))
/* ... don't work, and these or some equivalent is essential on i386 to
 * free enough registers for do_syscall6 to be compilable. So for now,
 * we are a separate file whose CFLAGS can control this. */
  
/* When we're called, it means we need to do the described syscall
 * with pre- and/or post-actions around it. There may or may not be a
 * defined replacement. We return through the call chain's return path.
 * In other words it's just like the body above. */
long __systrap_call_handler_slow(struct generic_syscall *gsp)
{
	if (__systrap_pre_handling) __systrap_pre_handling(gsp);
	long ret;
	if (replaced_syscalls[gsp->syscall_number])
	{
		ret = replaced_syscalls[gsp->syscall_number](gsp);  /* XXX: this skips the post-syscall handling! FIXME! */
	}
	else
	{
		ret = do_generic_syscall_and_fixup(gsp);
		/* this does the post-syscall handling as part of do_generic_syscall_and_fixup,
		 * but instead it should happen here (and above). */
	}
	if (__systrap_post_handling) __systrap_post_handling(gsp, ret);
	return ret;
}
