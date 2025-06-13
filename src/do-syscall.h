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
			  "pop %%ebp \n"
#endif
	  : [ret]  "+a" (ret_op)
	  : [arg0] "rm" ((long int) gsp->args[0])
	  , [arg1] "rm" ((long int) gsp->args[1])
	  , [arg2] "rm" ((long int) gsp->args[2])
	  , [arg3] "rm" ((long int) gsp->args[3])
	  , [arg4] "rm" ((long int) gsp->args[4])
	  , [arg5] "rm" ((long int) gsp->args[5])
	  : "%"stringifx(argreg0), "%"stringifx(argreg1), "%"stringifx(argreg2),
	    "%"stringifx(argreg3),
	    "%"stringifx(argreg4), /*"%"stringifx(argreg5),*/ DO_SYSCALL_CLOBBER_LIST(6));
	return ret_op;
}

__attribute__((always_inline,gnu_inline))
extern inline long int
do_real_syscall(struct generic_syscall *gsp)
{
	return do_syscall6(gsp);
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
	/* eax */ unsigned long syscall_num_unused /* syscall num from eax */,
	/* edx */ int *parent_tid_unused,
	/* ecx */ uintptr_t new_stack
#else
#error "Unrecognised architecture."
#endif
)
{
#if defined(__i386__)
	uintptr_t sp_on_clone = ((uintptr_t) __builtin_frame_address()) - sizeof (long);
#endif
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
#define ALIGN 64
	if (   (uintptr_t) copydest_end % ALIGN
		!= (uintptr_t) copysrc_end % ALIGN)
	{
		ssize_t difference = (uintptr_t) copydest_end % ALIGN
		 - (uintptr_t) copysrc_end % ALIGN;
		assert(0 == difference % sizeof (uintptr_t));
		copydest_start -= difference / sizeof (uintptr_t);
		copydest_end -= difference / sizeof (uintptr_t);
		assert((uintptr_t) copydest_end % ALIGN == (uintptr_t) copysrc_end % ALIGN);
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

enum special_syscall
{
	NOT_SPECIAL,
#if defined(__linux__)
	SPECIAL_SYSCALL_CLONE_NEWSTACK,
#elif defined(__FreeBSD__)
#endif
	SPECIAL_SYSCALL_MAX
};

extern inline __attribute__((always_inline,gnu_inline))
enum special_syscall is_special_syscall(struct generic_syscall *gsp)
{
	if (gsp->syscall_number == __NR_clone && gsp->args[1] /* newstack */ != 0)
	{ return SPECIAL_SYSCALL_CLONE_NEWSTACK; }
	return NOT_SPECIAL;
}

#ifdef __linux__
extern inline long
__attribute__((always_inline,gnu_inline))
do_clone(struct generic_syscall *gsp);
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
#ifdef __linux__
		case SPECIAL_SYSCALL_CLONE_NEWSTACK:
			ret = do_clone(gsp); // does its own fixup
			break;
#endif
		
		default:
			break;
	}
	__systrap_post_handling(gsp, ret, /* do_caller_fixup */ 0);
}

extern inline long
__attribute__((always_inline,gnu_inline))
do_clone(struct generic_syscall *gsp)
{
	// we should have a new top of stack
	assert(gsp->args[1] /* a.k.a. 'stack' argument to raw clone() syscall */);
	void *post_zap_top_of_stack = (void*) gsp->args[1];
	// our new stack should be aligned
	assert(0 == (uintptr_t) post_zap_top_of_stack %
#if defined(__x86_64__)
		16
#elif defined(__i386__)
		4
#else
#error "Unsupported architecture."
#endif
	);
	// the stack should have been aligned at the trap site
	// assert(0 == (uintptr_t) gsp->saved_context->uc.uc_mcontext.MC_REG_SP % STACK_ALIGN);
	/* HMM. Actually it might not be! So what can we do?
	 * I'm suspecting that Linux does not need $rsp to be 16-byte-aligned,
	 * but that clone() *does*. (For now, just a theory!) See below. */

	/* We are doing *two* sigreturns! One on our stack, one on the new stack
	 * in the new cloned thread.
	 *
	 * We need to initialize the new stack with the contents it needs
	 * for this second sigreturn to work. Note that the second sigreturn will
	 * resume from exactly the same place in the client code as the original sigreturn.
	 * It's the stack that will be different. (Our second sigreturn is on a stack that
	 * never signalled!) */
	uintptr_t *orig_sp;
	uintptr_t *orig_bp;
#if defined(__x86_64__)
	__asm__ volatile ("movq %%rsp, %0" : "=rm"(orig_sp) : : );
	__asm__ volatile ("movq %%rbp, %0" : "=rm"(orig_bp) : : );
#elif defined(__i386__)
	__asm__ volatile ("movl %%esp, %0" : "=rm"(orig_sp) : : );
	__asm__ volatile ("movl %%ebp, %0" : "=rm"(orig_bp) : : );
#else
#error "Unsupported architecture."
#endif
	/* There may be stuff on the sigframe above the struct ibcs_sigframe.
	 * We use the saved SP to work out how much to copy.
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
		  "mov %[arg0], %%"stringifx(argreg0)" \n\
		   mov %[arg1], %%"stringifx(argreg1)" \n\
		   mov %[arg2], %%"stringifx(argreg2)" \n\
		   mov %[arg3], %%"stringifx(argreg3)" \n\
		   mov %[arg4], %%"stringifx(argreg4)"  \n"
	#if defined(__x86_64__)
		  "mov %[gsp],  %%r11 \n"    /* Put gsp in r11, for copy_to_new_stack */
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
		  "movq %%r11, %%r8\n"       /* r8 is arg4 of sysv call */
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
		   "je .L001$           # if taken, it means we are the child with a new stack \n"
		   /* The compiler-generated
		    * code in both parent and child may still need the BP to refer to locals.
		    * When we take the 'je' above, to .001 below, our old stack is gone and above we
		    * preemptively put swizzled_bp in ebp/rbp, having pushed the old ebp/rbp.
		    * That is correct, for the child, although we must adjust the SP to drop the
		    * unneeded BP save slot on the new stack. In the parent, we instead use this
		    * saved value to restore the correct (parent) BP. */
		   "popq %%rbp           # restore the correct (parent) BP \n"
		   "jmp .L002$ \n"
		".L001$:\n"
		   "addq $0x8, %%rsp    # discard the unwanted saved BP (actually uninitialized/zero in the child) \n"
		   "jmp .L002$ \n"
	#elif defined(__i386__)
		  "push %%ebp\n"        /* See below. We need this to restore BP in the parent... */
		  "push %%eax\n"
		  "push %%edx\n"
		  "push %%ecx\n"
		  "call copy_to_new_stack\n" /* RECEIVES eax (syscall num), edx (argreg2),
		                              * ecx (argreg1); those regs are also the only clobbers.
		                              * FIXME: it needs sp_at_clone and gsp too.
		         * FIXME: sort out clobbers: syscall num, argreg1, argreg2
		         * FIXME: test it, you idiot! */
		  "pop %%ecx\n"
		  "pop %%edx\n"
		  "pop %%eax\n"
		   /* begin PERFORM_SYSCALL expansion */
		   stringifx(SYSCALL_INSTR) "\n"
		   /* end PERFORM_SYSCALL expansion */
		   /* Immediately test: did our stack actually get zapped? */
		   "cmpl %%esp, %%"stringifx(argreg1)"\n"
		   "je .L001$ \n"
		   "pop %%ebp           # restore the correct (parent) BP \n"\n"
		   "jmp .L002$ \n"
		".L001$:\n"
		   "add $0x4, %%esp    # discard the unwanted saved BP (actually uninitialized/zero in the child) \n"
		   "jmp .L002$ \n"
	#else
	#error "Unsupported architecture."
	#endif
		   /* For all our locals, either
		    * - the compiler chose a register *not* clobbered by the syscall (declared below), or
		    * - the compiler put them on the stack and we copied/rewrote them appropriately.
		    * So things should continue to Just Work from here... in particular
		    * we should have a working %rbp and %rsp in both parent and child.
		    */
		".L002$:\n"
		   "nop\n"
		  : [ret]  "+a" (ret_op)
#ifndef __i386__
		  , [gsp] "=m"(gsp)  /* gsp is a fake output, i.e. a clobber */
		   /* We list gsp it as a memory output so that the compiler thinks it's
		    * clobbered. That way, it will keep it in its stack slot during the asm block,
		    * and will reload it later if it's needed in a register. Of course it
		    * will be reloading the new, fixed-up version, but that is all transparent
		    * to the compiler. */
#else
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
		  : [arg0] "m" ((long int) gsp->args[0])
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

#endif
