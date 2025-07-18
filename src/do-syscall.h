#ifndef DO_SYSCALL_H_
#define DO_SYSCALL_H_

#include "raw-syscalls-impl.h" /* always include raw-syscalls first, and let it do the asm includes */

#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#ifndef __FreeBSD__ /* FIXME: use HAVE_ALLOCA_H_ when we are autotools'd */
#include <alloca.h>
#endif
#ifdef __FreeBSD__
#include <stdlib.h>
#endif
//#include <string.h>
#include <sys/syscall.h>
#include <stdarg.h>

extern int debug_level;

#include "vas.h" /* from librunt */
#include "systrap.h"
#include "systrap_private.h"
#include "instr.h"

// make a noncommital declaration of __assert_fail
void __assert_fail() __attribute__((noreturn));

extern uintptr_t our_load_address;

/* FIX_STACK_ALIGNMENT is in raw-syscalls-impl.h, included above */
#define PERFORM_SYSCALL	 \
	  FIX_STACK_ALIGNMENT "  \n\
	 "stringifx(SYSCALL_INSTR)		" \n\
	 "UNFIX_STACK_ALIGNMENT" \n"

void __attribute__((weak,visibility("protected")))
__systrap_post_handling(struct generic_syscall *gsp, long int ret, _Bool do_caller_fixup);

/* I wrote this using old-style initializers because we don't want to
 * zero-clobber registers that are unrelated to the call. But those
 * struct fields are ignored by the corresponding do_syscallN calls,
 * so that wouldn't happen anyway. Oh well... it's briefer too. */
#define MKGS0(op)                         { NULL, op }
#define MKGS1(op, a1)                     { NULL, op, { (long) a1 } }
#define MKGS2(op, a1, a2)                 { NULL, op, { (long) a1, (long) a2 } }
#define MKGS3(op, a1, a2, a3)             { NULL, op, { (long) a1, (long) a2, (long) a3 } }
#define MKGS4(op, a1, a2, a3, a4)         { NULL, op, { (long) a1, (long) a2, (long) a3, (long) a4 } }
#define MKGS5(op, a1, a2, a3, a4, a5)     { NULL, op, { (long) a1, (long) a2, (long) a3, (long) a4, (long) a5 } }
#define MKGS6(op, a1, a2, a3, a4, a5, a6) { NULL, op, { (long) a1, (long) a2, (long) a3, (long) a4, (long) a5, (long) a6 } }

extern inline long int 
__attribute__((always_inline,gnu_inline))
do_syscall0(struct generic_syscall *gsp)
{
	long int ret_op = (long int) gsp->syscall_number;

	__asm__ volatile (PERFORM_SYSCALL
	  : [ret] "+a" (ret_op) :
	  : DO_SYSCALL_CLOBBER_LIST(0));

	return ret_op;
}

extern inline long int
__attribute__((always_inline,gnu_inline))
do_syscall1(struct generic_syscall *gsp)
{
	long int ret_op = (long int) gsp->syscall_number;

	__asm__ volatile (
			  "mov %[arg0], %%"stringifx(argreg0)" \n"
			   PERFORM_SYSCALL
	  : [ret]  "+a" (ret_op)
	  : [arg0] "rm" ((long int) gsp->args[0])
	  : "%"stringifx(argreg0), DO_SYSCALL_CLOBBER_LIST(1));

	return ret_op;
}

extern inline long int 
__attribute__((always_inline,gnu_inline))
do_syscall2(struct generic_syscall *gsp)
{
	long int ret_op = (long int) gsp->syscall_number;
	__asm__ volatile (
			  "mov %[arg0], %%"stringifx(argreg0)" \n\
			   mov %[arg1], %%"stringifx(argreg1)" \n"
			   PERFORM_SYSCALL
	  : [ret]  "+a" (ret_op)
	  : [arg0] "rm" ((long int) gsp->args[0])
	  , [arg1] "rm" ((long int) gsp->args[1])
	  : "%"stringifx(argreg0), "%"stringifx(argreg1), DO_SYSCALL_CLOBBER_LIST(2));

	return ret_op;
}

extern inline long int 
__attribute__((always_inline,gnu_inline))
do_syscall3(struct generic_syscall *gsp)
{
	long int ret_op = (long int) gsp->syscall_number;
	__asm__ volatile (
			  "mov %[arg0], %%"stringifx(argreg0)" \n\
			   mov %[arg1], %%"stringifx(argreg1)" \n\
			   mov %[arg2], %%"stringifx(argreg2)" \n"
			   PERFORM_SYSCALL
	  : [ret]  "+a" (ret_op)
	  : [arg0] "rm" ((long int) gsp->args[0])
	  , [arg1] "rm" ((long int) gsp->args[1])
	  , [arg2] "rm" ((long int) gsp->args[2])
	  : "%"stringifx(argreg0), "%"stringifx(argreg1), "%"stringifx(argreg2),
	    DO_SYSCALL_CLOBBER_LIST(3));

	return ret_op;
}

extern inline long int
__attribute__((always_inline,gnu_inline)) 
do_syscall4(struct generic_syscall *gsp)
{
	long int ret_op = (long int) gsp->syscall_number;
	__asm__ volatile (
			  "mov %[arg0], %%"stringifx(argreg0)" \n\
			   mov %[arg1], %%"stringifx(argreg1)" \n\
			   mov %[arg2], %%"stringifx(argreg2)" \n\
			   mov %[arg3], %%"stringifx(argreg3)" \n"
			   PERFORM_SYSCALL
	  : [ret]  "+a" (ret_op)
	  : [arg0] "rm" ((long int) gsp->args[0])
	  , [arg1] "rm" ((long int) gsp->args[1])
	  , [arg2] "rm" ((long int) gsp->args[2])
	  , [arg3] "rm" ((long int) gsp->args[3])
	  : "%"stringifx(argreg0), "%"stringifx(argreg1), "%"stringifx(argreg2), "%"stringifx(argreg3),
	    DO_SYSCALL_CLOBBER_LIST(4));

	return ret_op;
}

extern inline long int
__attribute__((always_inline,gnu_inline))
do_syscall5(struct generic_syscall *gsp)
{
	long int ret_op = (long int) gsp->syscall_number;
	__asm__ volatile (
			  "mov %[arg0], %%"stringifx(argreg0)" \n\
			   mov %[arg1], %%"stringifx(argreg1)" \n\
			   mov %[arg2], %%"stringifx(argreg2)" \n\
			   mov %[arg3], %%"stringifx(argreg3)" \n\
			   mov %[arg4], %%"stringifx(argreg4)"  \n"
			   PERFORM_SYSCALL
	  : [ret]  "+a" (ret_op)
	  : [arg0] "rm" ((long int) gsp->args[0])
	  , [arg1] "rm" ((long int) gsp->args[1])
	  , [arg2] "rm" ((long int) gsp->args[2])
	  , [arg3] "rm" ((long int) gsp->args[3])
	  , [arg4] "rm" ((long int) gsp->args[4])
	  : "%"stringifx(argreg0), "%"stringifx(argreg1), "%"stringifx(argreg2), 
	    "%"stringifx(argreg3), "%"stringifx(argreg4), DO_SYSCALL_CLOBBER_LIST(5));

	return ret_op;
}

extern inline long int
__attribute__((always_inline,gnu_inline)) 
do_syscall6(struct generic_syscall *gsp)
{
	long int ret_op = (long int) gsp->syscall_number;
	__asm__ volatile (
			  "mov %[arg0], %%"stringifx(argreg0)" \n\
			   mov %[arg1], %%"stringifx(argreg1)" \n\
			   mov %[arg2], %%"stringifx(argreg2)" \n\
			   mov %[arg3], %%"stringifx(argreg3)" \n\
			   mov %[arg4], %%"stringifx(argreg4)" \n\
			 "
#ifdef __i386__
			  "push %%ebp \n"
#endif
			  "mov %[arg5], %%"stringifx(argreg5)" \n"
			   PERFORM_SYSCALL
#ifdef __i386__
			  "pop %%ebp \n"    /* handy is never a clone() or clone3() -- our stack lives */
#endif
	  : [ret]  "+a" (ret_op)
#ifdef __i386__
	  : [arg0] "m" ((long int) gsp->args[0])
	  , [arg1] "m" ((long int) gsp->args[1])
	  , [arg2] "m" ((long int) gsp->args[2])
	  , [arg3] "m" ((long int) gsp->args[3])
	  , [arg4] "m" ((long int) gsp->args[4])
	  , [arg5] "m" ((long int) gsp->args[5])
	  : "%"stringifx(argreg0), "%"stringifx(argreg1), "%"stringifx(argreg2),
	    "%"stringifx(argreg3), "%"stringifx(argreg4),
	    /*"%"stringifx(argreg5), -- argreg5 is %ebp, which the compiler knows
	     * is special, so does not allow us to mention in a clobber list. And
	     * it's OK, because we don't clobber it! Witness the pushes and pops above. */
	    DO_SYSCALL_CLOBBER_LIST(6)
#else
	  : [arg0] "rm" ((long int) gsp->args[0])
	  , [arg1] "rm" ((long int) gsp->args[1])
	  , [arg2] "rm" ((long int) gsp->args[2])
	  , [arg3] "rm" ((long int) gsp->args[3])
	  , [arg4] "rm" ((long int) gsp->args[4])
	  , [arg5] "rm" ((long int) gsp->args[5])
	  : "%"stringifx(argreg0), "%"stringifx(argreg1), "%"stringifx(argreg2),
	    "%"stringifx(argreg3), "%"stringifx(argreg4), "%"stringifx(argreg5),
	    DO_SYSCALL_CLOBBER_LIST(6)
#endif
	);
	return ret_op;
}

__attribute__((always_inline,gnu_inline))
extern inline long int
do_real_syscall(struct generic_syscall *gsp)
{
	return do_syscall6(gsp);
}

enum special_syscall
{
	NOT_SPECIAL,
	SPECIAL_SYSCALL_SIGRETURN,
#if defined(__linux__)
	SPECIAL_SYSCALL_CLONE_NEWSTACK,
	SPECIAL_SYSCALL_CLONE3_NEWSTACK,
#elif defined(__FreeBSD__)
#endif
	SPECIAL_SYSCALL_MAX
};
	
#ifndef SYS_clone3
#define SYS_clone3 435
#endif
#ifndef __NR_clone3
#define __NR_clone3 SYS_clone3
#endif
typedef unsigned long long u64;
// from the man page
struct clone_args {
   u64 flags;        /* Flags bit mask */
   u64 pidfd;        /* Where to store PID file descriptor
                        (pid_t *) */
   u64 child_tid;    /* Where to store child TID,
                        in child's memory (pid_t *) */
   u64 parent_tid;   /* Where to store child TID,
                        in parent's memory (int *) */
   u64 exit_signal;  /* Signal to deliver to parent on
                        child termination */
   u64 stack;        /* Pointer to lowest byte of stack */
   u64 stack_size;   /* Size of stack */
   u64 tls;          /* Location of new TLS */
   u64 set_tid;      /* Pointer to a pid_t array
                        (since Linux 5.5) */
   u64 set_tid_size; /* Number of elements in set_tid
                        (since Linux 5.5) */
   u64 cgroup;       /* File descriptor for target cgroup
                        of child (since Linux 5.7) */
};

#if defined(SYS_sigreturn) && !defined(__NR_sigreturn)
#define __NR_sigreturn SYS_sigreturn
#endif

#if defined(__linux__) && defined(__x86_64__) && !defined(__NR_rt_sigreturn)
#define __NR_rt_sigreturn SYS_rt_sigreturn
#endif
#if !defined(__NR_sigreturn) && defined(__NR_rt_sigreturn)
#define __NR_sigreturn __NR_rt_sigreturn
#endif

extern inline __attribute__((always_inline,gnu_inline))
enum special_syscall is_special_syscall(struct generic_syscall *gsp)
{
	if (gsp->syscall_number == __NR_sigreturn
#if defined(__linux__) && defined(__x86_64__)
			|| gsp->syscall_number == __NR_rt_sigreturn
#endif
	) {
		return SPECIAL_SYSCALL_SIGRETURN;
	}
#ifdef __linux__
	if (gsp->syscall_number == __NR_clone && gsp->args[1] /* newstack */ != 0)
	{ return SPECIAL_SYSCALL_CLONE_NEWSTACK; }
	if (gsp->syscall_number == __NR_clone3 && ((struct clone_args *) gsp->args[0])->stack != 0)
	{ return SPECIAL_SYSCALL_CLONE3_NEWSTACK; }
#endif
	return NOT_SPECIAL;
}

extern inline void
__attribute__((always_inline,gnu_inline,noreturn))
do_sigreturn(struct generic_syscall *gsp);
#ifdef __linux__
extern inline long
__attribute__((always_inline,gnu_inline))
do_clone(struct generic_syscall *gsp);
extern inline long
__attribute__((always_inline,gnu_inline))
do_clone3(struct generic_syscall *gsp);
#endif

extern inline void
__attribute__((always_inline,gnu_inline))
do_generic_syscall_and_fixup(struct generic_syscall *gsp)
{
	long ret;
	switch (is_special_syscall(gsp))
	{
		case NOT_SPECIAL:
			ret = do_real_syscall(gsp);            /* always inlined */
			fixup_sigframe_for_return(gsp->saved_context, ret,
				trap_len(&gsp->saved_context->uc.uc_mcontext), NULL);
			break;
		case SPECIAL_SYSCALL_SIGRETURN:
			do_sigreturn(gsp);
			break; // never hit -- sigreturn never returns
#ifdef __linux__
		case SPECIAL_SYSCALL_CLONE_NEWSTACK:
			ret = do_clone(gsp); // does its own fixup
			break;
		case SPECIAL_SYSCALL_CLONE3_NEWSTACK:
			ret = do_clone3(gsp); // does its own fixup
			break;
#endif
		default:
			break;
	}
	__systrap_post_handling(gsp, ret, /* do_caller_fixup */ 0);
}

/* At least clone(), and perhaps other system calls, will zap the stack.
 * This is a problem for us, because of our long return path.
 * Our normal return path is
 * - we return to handle_sigill()
 * - its on-stack return address is aliased by our ibcs_sigframe's pretcode
 * - this points to __restore / __restore_rt
 * - that does a sigreturn with the on-stack sigcontext, restoring the caller's registers.
 *
 * The general approach is to pre-copy the stack contents into the new stack,
 * immediately before we do the syscall. The stack contents includes the
 * generic_syscall struct, to which we have a pointer 'gsp'.
 * Immediately after the syscall, if the stack was zapped,
 * we swizzle gsp to point to the copy of this structure that we made on the new stack.
 * All this is done in inline assembly.
 *
 * We normally also have to fix up the caller's
 * - eax/rax, with the return value
 * - eip/rip, with the faulting instr + N bytes
 * but in this case we *also* have to fix up the caller's
 * - esp/rsp, with the equivalent offset on the new stack.
 *
 * Complication 1: when copying the stack, we also have to fix up stack-internal
 * pointers so that they point into the new stack.
 */
__attribute__((used,noinline))
#if defined(__i386__)
__attribute__((regparm(3)))
#endif
static void *copy_to_new_stack(
#if defined(__x86_64__)
	/* rdi */ unsigned long flags_unused,
	/* rsi */ uintptr_t new_stack,
	/* rdx */ int *parent_tid_unused,
	/* rcx */ uintptr_t sp_on_clone,
	/* r8 */  struct generic_syscall *gsp
#elif defined(__i386__)
	/* eax */ uintptr_t sp_on_clone,
	/* edx */ struct generic_syscall *gsp,
	/* ecx */ uintptr_t new_stack
#else
#error "Unrecognised architecture."
#endif
)
{
	uintptr_t *copysrc_start = (uintptr_t*) sp_on_clone;
	uintptr_t *copysrc_end = (uintptr_t*) (gsp->saved_context->uc.uc_mcontext.MC_REG_SP);
	size_t nwords_to_copy = copysrc_end - copysrc_start;
	size_t nbytes_to_copy = sizeof (*copysrc_start) * nwords_to_copy;

	/* Sanity: we expect the syscall ctxt block to be on *this* stack, so above current esp.
	 * FIXME: tighter check, and hard-abort if it fails (even when NDEBUG). */
	assert((uintptr_t) gsp > (uintptr_t) copysrc_start);
	/* Sanity: the block runs in the direction we expect, i.e. upwards */
	assert((uintptr_t) copysrc_end > (uintptr_t) copysrc_start);
	/* Sanity: we are not copying implausibly much. */
	assert((uintptr_t) copysrc_end - (uintptr_t) copysrc_start < 0x10000u);

	/* The new stack region has to match the alignment of the old stack region,
	 * i.e. corresponding addresses have to be congruent modulo ALIGN.
	 * If it doesn't match, adjust destination downwards s.t. it does. */
	uintptr_t *copydest_end = (uintptr_t *) new_stack;
	uintptr_t *copydest_start = ((uintptr_t *) new_stack) - nwords_to_copy;
#if 1 /* all arches for now... i.e. both 32- and 64-bit x86. Seems to be the XSAVE area? */
#define SIGFRAME_ALIGN 64
#endif
	if (   (uintptr_t) copydest_end % SIGFRAME_ALIGN
		!= (uintptr_t) copysrc_end % SIGFRAME_ALIGN)
	{
		ssize_t difference = (uintptr_t) copydest_end % SIGFRAME_ALIGN
		 - (uintptr_t) copysrc_end % SIGFRAME_ALIGN;
		assert(0 == difference % sizeof (uintptr_t));
		/* if difference > 0, it means copydest_end was aligned to a higher offset
		 * than copysrc_end. */
		if (difference < 0) difference = SIGFRAME_ALIGN + /* negative */ difference;
		copydest_start -= difference / sizeof (uintptr_t);
		copydest_end -= difference / sizeof (uintptr_t);
		assert((uintptr_t) copydest_end % SIGFRAME_ALIGN
			 == (uintptr_t) copysrc_end % SIGFRAME_ALIGN);
	}
	long fixup_delta_nbytes = (uintptr_t) copydest_end - (uintptr_t) copysrc_end;

	/* We shouldn't be copying more than a page (-epsilon) of stuff, because
	 * we can't know that the cloning code has allocated more stack than that. */
	assert(nbytes_to_copy < MIN_PAGE_SIZE - sizeof (void*));
	/* Do the copy */
	memcpy(copydest_start, copysrc_start, nbytes_to_copy);
	/* Do the fixup pass */
	uintptr_t *p_dest = copydest_start;
	for (uintptr_t *p_src = copysrc_start; p_src != copysrc_end; ++p_src, ++p_dest)
	{
		/* Relocate any word we copy if it's a stack address. HMM.
		 * FIXME: use the struct sigframe structure to identify what to fix up, i.e.
		 * only a statically enumerated set of words need fixing up in this way.
		 * For now, we take any word that looks like a pointer within the copied region.
		 *
		 * TODO: within the copied region, where is the sigframe? I think we should
		 * probably take this explicitly as an argument. */
		if (*p_src < (uintptr_t) copysrc_end && *p_src >= (uintptr_t) copysrc_start)
		{
			*p_dest += fixup_delta_nbytes;
		}
	}
	return (void*) copydest_start;
}


#if defined(__x86_64__)
#define STACK_ALIGN 16
#elif defined(__i386__)
#define STACK_ALIGN 4
#else
#error "Unsupported architecture."
#endif

extern inline long
__attribute__((always_inline,gnu_inline))
do_clone(struct generic_syscall *gsp)
{
	// we should have a new top of stack
	assert(gsp->args[1] /* a.k.a. 'stack' argument to raw clone() syscall */);
	void *post_zap_top_of_stack = (void*) gsp->args[1];
	// our new stack should be aligned
	assert(0 == (uintptr_t) post_zap_top_of_stack % STACK_ALIGN);

	/* We are doing *two* sigreturns! One on our stack, one on the new stack
	 * in the new cloned thread.
	 *
	 * We need to initialize the new stack with the contents it needs
	 * for this second sigreturn to work. Note that the second sigreturn will
	 * resume from exactly the same place in the client code as the original sigreturn.
	 * It's the stack that will be different. (Our second sigreturn is on a stack that
	 * never signalled!)
	 *
	 * There may be stuff on the sigframe above the struct ibcs_sigframe.
	 * We use the saved (syscall site's) SP to work out how much to copy.
	 * Remember: the stack pointer points to the "stack's bottom-most valid word" (SysV i386 PSABI).

     our stack                                         new stack
     :   ...  :
__  X|________|<-- sp at clone() site                 Y.________ <--stack limit! == post_zap_top_of_stack
 ^^  | . . .  |\                                       | . . .  |\
 ||  |  . . . | sigframe stuff                         |  . . . | COPY of sigframe stuff
Z||Z'|________|/    incl. saved ip = clone site (1)    |________|/    incl saved ip = clone site (AGAIN; YES)
 |v  | . . .  |\ us a.k.a. handle_sigill               | . . .  |\  COPY of us
 v___|__-_-_-_|/ <-- sp at time of syscall             |__-_-_-_|/ <-- hacked sp we give to clone()

                      ... the - - -  data might not be copied so had better not be important!

	 * The idea is that after sigreturn in the child, sp == post_zap_top_of_stack (Y)
	 * and IP == the instruction after the trapping clone (i.e. same as in the parent).
	 *
	 * Q. How do we fix up the IP?
	 * A. We don't! The raw clone does not take a new code address.
	 *    Instead it's the job of the invoking code, executing in the
	 *    child context, to jump to the new thread's code. In glibc and the like
	 *    there is a wrapper function, with a different signature, which performs this.
	 *    As long as we return the right return value (0 in the child) and the right
	 *    stack pointer, this code should do its job correctly.
	 *
	 * Note that there are two offsets in play:
	 *
	 *  X-Y, which is the distance between the old and new stack, and is easily known.
	 *        Pointers within the stack get adjusted by this offset for the new context.
	 *  Z  , which is the stack depth we are adding with our logic and the sigframe.
	 *        We need this for setting correctly the new SP in the child, so it can
	 *        resume through the sigframe machinery. We cannot calculate it easily in C
	 *        code because the compiler may adjust the stack pointer. Instead we call a
	 *        helper function from asm, passing the actual %rsp we will use at the clone
	 *        call. That helper can calculate Z accurately, and is also responsible for
	 *        generating the final new hacked SP (=Y-Z) we use for the cloned child.
	 */

	/* We have to use one big asm in order to keep stuff
	 * in registers long enough to call our helper.
	 * The basic idea is that everything we might need, if
	 * our stack gets zapped, is copied to the *new* stack.
	 */
	long int ret_op = (long int) gsp->syscall_number;
	__asm__ volatile (
	#if defined(__x86_64__) /* XXX: rationalise this by combining with later pops*/
		  "mov %[arg0], %%"stringifx(argreg0)" \n\
		   mov %[arg1], %%"stringifx(argreg1)" \n\
		   mov %[arg2], %%"stringifx(argreg2)" \n\
		   mov %[arg3], %%"stringifx(argreg3)" \n\
		   mov %[arg4], %%"stringifx(argreg4)"  \n"
		  "mov %[gsp],  %%r12 \n"    /* Put gsp in r12 (our extra clobber), for copy_to_new_stack */
		  "pushq %%rbp\n"            /* See below. We need this to restore BP in the parent... */
		   /* begin PERFORM_SYSCALL replacement */
		  "movq %%rsp, %%rcx\n"      /* rcx will form arg3 of sysv call, i.e. sp_at_clone */
		  "pushq %%rax\n"
		  "pushq %%rdx\n"
		  "pushq %%rsi\n"
		  "pushq %%rdi\n"
		  "pushq %%r8\n"
		  "pushq %%r9\n"
		  "pushq %%r10\n"
		  "pushq %%r11\n"
		  "movq %%r12, %%r8\n"       /* r8 is arg4 of sysv call */
		  FIX_STACK_ALIGNMENT
		  "callq copy_to_new_stack\n" /* RECEIVES: flags_unused in rdi(sysvargreg0),
		                                new_stack a.k.a. argreg1 in rsi(sysvargreg1),
		                                parent_tid_unused in rdx(sysvargreg2),
		                                rsp_on_clone in rcx(sysvargreg3),
		                                gsp in r8(sysvargreg4).
		                                CLOBBERS: rax (syscallno), rcx (unused), rdx (kargreg2), 
		                                rsi (kargreg1), rdi (kargreg0), r8 (kargreg4), r9 (kargreg5),
		                                r10 (kargreg3), r11 (holds gsp)
		                                so we have to reload stuff.
		                                RETURNS: actual new stack to use */
		  UNFIX_STACK_ALIGNMENT
		  "popq %%r11\n"
		  "popq %%r10\n"
		  "popq %%r9\n"
		  "popq %%r8\n"
		  "popq %%rdi\n"
		  "popq %%rsi\n"
		  "popq %%rdx\n"
		  "movq %%rax, %%rsi\n"       /* copy_to_new_stack returned the actual new stack to use */
		  "popq %%rax\n"
		  "addq %%rsi, %%rbp\n"  /* Swizzle bp to point into the child's stack, and pre-emptively... */
		  "subq %%rsp, %%rbp\n"  /* set this as the BP. Compiler-generated code later in this function
		                           might need to reference the BP. In the non-child case we restore the
		                           parent BP that we pushed above. */
		   stringifx(SYSCALL_INSTR) "\n"
		   /* end PERFORM_SYSCALL replacement */
		   /* Immediately test: did our stack actually get zapped? */
		   "cmpq %%rsp, %%"stringifx(argreg1)"\n"
		   "je 1f           # if taken, it means we are the child with a new stack \n"
		   /* The compiler-generated
		    * code in both parent and child may still need the BP to refer to locals.
		    * When we take the 'je' above, to .001 below, our old stack is gone and above we
		    * preemptively put swizzled_bp in ebp/rbp, having pushed the old ebp/rbp.
		    * That is correct, for the child, although we must adjust the SP to drop the
		    * unneeded BP save slot on the new stack. In the parent, we instead use this
		    * saved value to restore the correct (parent) BP. */
		   "popq %%rbp           # restore the correct (parent) BP \n"
		   "jmp 2f \n"
		"1:\n"
		   "addq $0x8, %%rsp    # discard the unwanted saved BP (actually uninitialized/zero in the child) \n"
		   "jmp 2f \n"
	#elif defined(__i386__)
		  "push %%ebp\n"        /* See below. We need this to restore BP in the parent... */
		       /* Now, our esp equals sp_at_clone. So put it in eax (first regparm3 arg)
		        * -- no need to save, as eax is a clobber of any syscall. */
		  "mov %%esp, %%eax\n"
		  "mov %[gsp], %%edx\n"
		  "mov %[arg1], %%ecx\n"
		  "call copy_to_new_stack\n" /* RECEIVES eax (sp_on_clone), edx (gsp),
		                              * ecx (kargreg1 / new_stack); those regs are also the only clobbers. */
		       /* Now our %eax contains the real new stack to use */
		   /* begin PERFORM_SYSCALL expansion */
		  "mov %%eax, %%"stringifx(argreg1)" \n"
		       /* Now set up the other arg regs */
		  "mov $%c[op], %%eax\n"
		  "mov %[arg0], %%"stringifx(argreg0)" \n"
		  /*     arg1   is initialized above!  */
		  "mov %[arg2], %%"stringifx(argreg2)" \n\
		   mov %[arg3], %%"stringifx(argreg3)" \n\
		   mov %[arg4], %%"stringifx(argreg4)"  \n"
		  "add %%"stringifx(argreg1)", %%ebp\n"  /* Swizzle bp to point into the child's stack, and pre-emptively... */
		  "sub %%esp, %%ebp\n"  /* set this as the BP. Compiler-generated code later in this function
		                           might need to reference the BP. In the non-child case we restore the
		                           parent BP that we pushed above. */
		   stringifx(SYSCALL_INSTR) "\n"
		   /* end PERFORM_SYSCALL expansion */
		   /* Immediately test: did our stack actually get zapped? */
		   "cmpl %%esp, %%"stringifx(argreg1)"\n"
		   "je 1f \n"
		   "pop %%ebp           # restore the correct (parent) BP \n"
		   "jmp 2f \n"
		"1:\n"
		   "add $0x4, %%esp    # discard the unwanted saved BP (actually uninitialized/zero in the child) \n"
		   "jmp 2f \n"
	#else
	#error "Unsupported architecture."
	#endif
		   /* For all our locals, either
		    * - the compiler chose a register *not* clobbered by the syscall (declared below), or
		    * - the compiler put them on the stack and we copied/rewrote them appropriately.
		    * So things should continue to Just Work from here... in particular
		    * we should have a working %rbp and %rsp in both parent and child.
		    */
		"2:\n"
		   "nop\n"
		  :
#ifndef __i386__
		    [ret]  "+a" (ret_op)
		  , [gsp] "+m"(gsp)  /* gsp is a fake output, i.e. a clobber */
		   /* We list gsp it as a memory in/out so that the compiler thinks it's
		    * clobbered. That way, it will keep it in its stack slot during the asm block,
		    * and will reload it later if it's needed in a register. Of course it
		    * will be reloading the new, fixed-up version, but that is all transparent
		    * to the compiler. */
#else
		    [ret]  "=a" (ret_op)
		  , [gsp] "=m"(gsp)  /* gsp is a fake output, i.e. a clobber */
		/* On 32-bit x86 this code is very sensitive to asm constraint-solvability.
		 * I have seen constraint solving fail following some innocuous changes
		 * such as:
		 *
		 *  turning on -fno-strict-aliasing
		 *
		 *  using asm to get the value of BP
		 *
		 *  introducing memcpy calls.
		 *
		 * For snarfing %ebp, it seemed the problem was triggered
		 * if swizzled_bp was used as an the output of
		 * *any* asm or builtin, even 'nop' like this.
		 *__asm__ ("nop" : "=r"(swizzled_bp) : : );
		 *
		 * Previously I worked around this in a sneaky way: our current
		 * %ebp is a fixed offset from the lowest stack address currently
		 * saved on the stack (assuming none of our locals points to a local).
		 * So when we do a copy-and-relocate of the stack (above), we
		 * snarf the first pointer we relocate. However, that seemed unreliable.
		 *
		 * For the moment I found that if we refrain from declaring 'gsp'
		 * as an output of the asm, it frees up enough slack in the constraints.
		 * However, this is dangerous as we haven't really told the compiler that
		 * it needs to reload gsp. And it really does need to reload gsp via BP,
		 * because that is the only memory that is definitely valid. */
#endif
		  :
#ifdef __i386__
			[op] "i"(__NR_clone),
#endif
		    [arg0] "m" ((long int) gsp->args[0])
		  , [arg1] "m" ((long int) gsp->args[1])
		  , [arg2] "m" ((long int) gsp->args[2])
		  , [arg3] "m" ((long int) gsp->args[3])
		  , [arg4] "m" ((long int) gsp->args[4])
		  : "%"stringifx(argreg0), "%"stringifx(argreg1), "%"stringifx(argreg2),
		    "%"stringifx(argreg3), "%"stringifx(argreg4), "memory", DO_SYSCALL_CLOBBER_LIST(5)
	);
	// FIXME: can we do this fixup before the clone, but
	// after the stack copy? We just fix up the copied context
	// on the stack, speculatively. Might be cleaner and fit with our
	// "walk the stack and fix up saved BPs only" idea, i.e. minimise
	// how many on-stack pointers have to work to get us to the sigreturn.
	fixup_sigframe_for_return(gsp->saved_context, /*post_zap_top_of_stack - sizeof (struct ibcs_sigframe), */
		ret_op, trap_len(&gsp->saved_context->uc.uc_mcontext),
		/* new_sp: we have a new sp only if we're the child.
		 * We can detect that using ret_op i.e. clone()'s return value. */
		(ret_op == 0) ? (void*) (gsp->args[1] /* see fake_arg1 comment above  */)
			: NULL);
	return ret_op;
}

extern inline long
__attribute__((always_inline,gnu_inline))
do_clone3(struct generic_syscall *gsp)
{
// XXX: x86-64 only for now
	long int ret_op = (long int) gsp->syscall_number;
	__asm__ volatile (
	#if defined(__x86_64__)
		  "mov %[arg0], %%"stringifx(argreg0)" \n\
		   mov %[arg1], %%"stringifx(argreg1)" \n"
		  "mov %[gsp],  %%r12 \n"    /* Put gsp in r12, for copy_to_new_stack */
		  "pushq %%rbp\n"            /* See below. We need this to restore BP in the parent... */
		   /* begin PERFORM_SYSCALL replacement */
		  "movq %%rsp, %%rcx\n"      /* rcx will form arg3 of sysv call, i.e. sp_at_clone */
		  "pushq %%rax\n"
		  /* begin clobber saves */
		  "pushq %%rdx\n"
		  "pushq %%rsi\n"
		  "movq %c[new_stack_offs](%%rdi), %%rsi\n" /* new_stack: get the base */
		  "addq %c[stack_size_offs](%%rdi), %%rsi\n" /* new_stack: make it the top */
		  "pushq %%rdi\n"
		  "pushq %%r8\n"
		  "pushq %%r9\n"
		  "pushq %%r10\n"
		  "pushq %%r11\n"
		  /* end clobber saves */
		  "movq %%r12, %%r8\n"       /* r8 is arg4 of ABI call */
		  FIX_STACK_ALIGNMENT
		  "callq copy_to_new_stack\n" /* RECEIVES: flags_unused in rdi(sysvargreg0),
		                                new_stack a.k.a. argreg1 in rsi(sysvargreg1),
		                                garbage_unused in rdx(sysvargreg2),
		                                rsp_on_clone in rcx(sysvargreg3),
		                                gsp in r8(sysvargreg4).
		                                CLOBBERS: rax (syscallno), rcx (unused), rdx (kargreg2), 
		                                rsi (kargreg1), rdi (kargreg0), r8 (kargreg4), r9 (kargreg5),
		                                r10 (kargreg3), r11 (holds gsp)
		                                so we have to reload stuff.
		                                RETURNS: *top* of the actual new stack to use */
		  UNFIX_STACK_ALIGNMENT
		  "movq %%rax, %%r12\n"        /* "expected sp value after clone" -- we need this later */
		  /* begin clobber restores */
		  "popq %%r11\n"
		  "popq %%r10\n"
		  "popq %%r9\n"
		  "popq %%r8\n"
		  "popq %%rdi\n"
		  "popq %%rsi\n"
		  "popq %%rdx\n"
		  /* end clobber restores */
		  /* copy_to_new_stack returned the *top*
		   * of the actual new stack to use, but clone3
		   * wants the bottom, which is unchanged!
		   * Instead we adjust the size downwards, first by
		   * subtracting new_stack (bigger) and then by adding %rax (smaller).
		   * We have to calculate new_stack first! */
		  "movq %c[new_stack_offs](%%rdi), %%r12\n" /* new_stack: get the base */
		  "addq %c[stack_size_offs](%%rdi), %%r12\n" /* new_stack: make it the top */
		  "subq %%r12, %c[stack_size_offs](%%rdi)\n" /* now adjust the new stack *size* that we pass */
		  "addq %%rax, %c[stack_size_offs](%%rdi)\n" /* r12 is still new_stack */
		  "addq %%rax, %%rbp\n"  /* Swizzle bp to point into the child's stack, and pre-emptively... */
		  "subq %%rsp, %%rbp\n"  /* set this as the BP. Compiler-generated code later in this function
		                           might need to reference the BP. In the non-child case we restore the
		                           parent BP that we pushed above. */
		  "popq %%rax\n"         /* Restore %rax now we're finished with copy_'s return value */
		  "subq $8,%%rbp\n"      /* In the subq above, our %%rsp was too small by one slot (8 bytes) because of the pushed %rax */
		   stringifx(SYSCALL_INSTR) "\n"
		   /* end PERFORM_SYSCALL replacement */
		   /* Immediately test: did our stack actually get zapped? */
		   "cmpq %%rsp, %%r12\n" /* are we the child? */
		   "je 1f           # if taken, it means we are the child with a new stack \n"
		   /* The compiler-generated
		    * code in both parent and child may still need the BP to refer to locals.
		    * When we take the 'je' above, to .001 below, our old stack is gone and above we
		    * preemptively put swizzled_bp in ebp/rbp, having pushed the old ebp/rbp.
		    * That is correct, for the child, although we must adjust the SP to drop the
		    * unneeded BP save slot on the new stack. In the parent, we instead use this
		    * saved value to restore the correct (parent) BP. */
		   "popq %%rbp           # restore the correct (parent) BP \n"
		   "jmp 2f \n"
		"1:\n"
		   "addq $0x8, %%rsp    # discard the unwanted saved BP (actually uninitialized/zero in the child) \n"
		   "jmp 2f \n"
#elif defined (__i386__)
		  "mov %[arg0], %%"stringifx(argreg0) /* ebx */" \n"
		  "push %%ebp\n"            /* See below. We need this to restore BP in the parent... */
		  "mov %%esp, %%eax\n"      /* ecx will form arg3 of sysv+regparm3 call, i.e. sp_at_clone */
		  /* save the old edx -- NOT a clobber, for a two-arg syscall */
		  "push %%edx\n"
		  "mov %[gsp], %%edx\n"
		  "mov %c[new_stack_offs](%%ebx), %%ecx\n" /* new_stack: get the base */
		  "add %c[stack_size_offs](%%ebx), %%ecx\n" /* new_stack: make it the top */
		  "call copy_to_new_stack\n" /* RECEIVES eax (sp_on_clone),
		                                         edx (gsp),
		                                         ecx (new_stack);
		                                and those regs are also the only clobbers. */
		  /* copy_to_new_stack returned the *top*
		   * of the actual new stack to use, but clone3
		   * wants the bottom, which is unchanged!
		   * Instead we adjust the size downwards, first by
		   * subtracting new_stack (reloaded %ecx, bigger) and then by adding %eax (smaller) */
		  "mov %c[new_stack_offs](%%ebx), %%ecx\n" /* new_stack: get the base */
		  "add %c[stack_size_offs](%%ebx), %%ecx\n" /* new_stack: make it the top */
		  "sub %%ecx, %c[stack_size_offs](%%ebx)\n"
		  "add %%eax, %c[stack_size_offs](%%ebx)\n"
		  "add %%eax, %%ebp\n"  /* Swizzle bp to point into the child's stack, and pre-emptively... */
		  "sub %%esp, %%ebp\n"  /* set this as the BP. Compiler-generated code later in this function
		                           might need to reference the BP. In the non-child case we restore the
		                           parent BP that we pushed above. */
		  "popl %%edx\n"          /* restore %edx that we saved earlier */
		  "sub $4,%%ebp\n"      /* In the sub above, our %%esp was too small by one slot (4 bytes) because of the pushed rdx */
		  "mov %%eax, %%edx\n"    /* edx is our other clobber, so stash the expected new sp there */
		  "mov $%c[op], %%eax\n"   /* Restore %eax now we're finished with copy_'s return value */
		  "mov %[arg1], %%ecx\n"   /* Reload %ecx, i.e. our arg1 */
		   stringifx(SYSCALL_INSTR) "\n"
		   /* end PERFORM_SYSCALL replacement */
		   /* Immediately test: did our stack actually get zapped? */
		   "cmp %%esp, %%edx\n"
		   "je 1f           # if taken, it means we are the child with a new stack \n"
		   /* The compiler-generated
		    * code in both parent and child may still need the BP to refer to locals.
		    * When we take the 'je' above, to .001 below, our old stack is gone and above we
		    * preemptively put swizzled_bp in ebp/rbp, having pushed the old ebp/rbp.
		    * That is correct, for the child, although we must adjust the SP to drop the
		    * unneeded BP save slot on the new stack. In the parent, we instead use this
		    * saved value to restore the correct (parent) BP. */
		   "popl %%ebp           # restore the correct (parent) BP \n"
		   "jmp 2f \n"
		"1:\n"
		   "add $0x4, %%esp    # discard the unwanted saved BP (actually uninitialized/zero in the child) \n"
		   "jmp 2f \n"
#else
#error "Unsupported architecture."
#endif
		   /* For all our locals, either
		    * - the compiler chose a register *not* clobbered by the syscall (declared below), or
		    * - the compiler put them on the stack and we copied/rewrote them appropriately.
		    * So things should continue to Just Work from here... in particular
		    * we should have a working %rbp and %rsp in both parent and child.
		    */
		"2:\n"
		   "nop\n"
		  :
#ifdef __i386__
		    [ret]  "=a" (ret_op)
#else
		    [ret]  "+a" (ret_op)
#endif
		  , [gsp] "+m"(gsp)  /* gsp is a fake output, i.e. a clobber */
		   /* We list gsp it as a memory output so that the compiler thinks it's
		    * clobbered. That way, it will keep it in its stack slot during the asm block,
		    * and will reload it later if it's needed in a register. Of course it
		    * will be reloading the new, fixed-up version, but that is all transparent
		    * to the compiler. */
		  :
#ifdef __i386__
            [op] "i" (__NR_clone3),
#endif
		    [arg0] "m" ((long int) gsp->args[0])
		  , [arg1] "m" ((long int) gsp->args[1])
		  , [new_stack_offs]  "i" (offsetof (struct clone_args, stack))
		  , [stack_size_offs] "i" (offsetof (struct clone_args, stack_size))
		  : "%"stringifx(argreg0), "%"stringifx(argreg1), "%ecx", "memory", DO_SYSCALL_CLOBBER_LIST(2)
	);
	fixup_sigframe_for_return(gsp->saved_context, ret_op,
		trap_len(&gsp->saved_context->uc.uc_mcontext),
		/* new_sp: we have a new sp only if we're the child.
		 * We can detect that using ret_op i.e. clone3()'s return value.
		 * XXX: it is possible to clone without replacing the stack, which
		 * is not handled correctly here. */
		(ret_op == 0) ? (void*) (
		           (uintptr_t)(((struct clone_args *) gsp->args[0])->stack)
		         + (uintptr_t)(((struct clone_args *) gsp->args[0])->stack_size)
		): NULL);
	return ret_op;
}


extern inline void
__attribute__((always_inline,gnu_inline,noreturn))
do_sigreturn(struct generic_syscall *gsp)
{
	/* To do a sigreturn, we simply restore the user's stack pointer
	 * to what it was at the site of the trap... i.e. do the same sigreturn
	 * that the original code was trying to do, just from a different code address.
	 *
	 * NOTE that the *user's* sigframe should NOT be one of our trap sites.
	 * So there is no need to fix it up!
	 *
	 * E.g. say we rewrote a __restore_rt s.t. its 'syscall' instead is 'ud2' and
	 * traps to us. We take the stack pointer at the time of the ud2, and do
	 * the sigreturn ourselves.
	 *
	 * We do it simply by restoring the stack pointer to its value at the site of
	 * the ud2 trap, and doing sigreturn. That sigreturn should receive the
	 * same sigframe that the sigreturn was trying to return through. That should
	 * include a *further* trap site. We are skipping *past* the sigframe
	 * that was caused by our trap, and heading straight for the actual
	 * sigframe that that first signal's handler was trying to resume with.
	 */
	long int ret_op = (long int) gsp->syscall_number; /* either sigreturn or rt_sigreturn */
	__asm__ volatile (
#if defined(__x86_64__)
		  "mov %[orig_sigframe_sp], %%rsp \n" /* stack pointer at the trapped sigreturn syscall */
#elif defined(__i386__)
		  "mov %[orig_sigframe_sp], %%esp \n" /* stack pointer at the trapped sigreturn syscall */
#else
#error "Unsupported architecture."
#endif
		   stringifx(SYSCALL_INSTR) "\n"
		  : [ret]  "+a" (ret_op)
		  : [orig_sigframe_sp] "r"(gsp->saved_context->uc.uc_mcontext.MC_REG_SP)
		  : "memory", DO_SYSCALL_CLOBBER_LIST(0)
	);
	/* We should never get here. */
	raw_exit(128 + SIGABRT);
}


#endif
