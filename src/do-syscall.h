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

/* HACK: sysdep */
extern inline _Bool
__attribute__((always_inline,gnu_inline))
zaps_stack(struct generic_syscall *gsp, void **p_new_sp)
{
#ifdef __FreeBSD__
	return 0;
#else
	if (gsp->syscall_number == __NR_clone && gsp->args[1] /* newstack */ != 0)
	{
		*p_new_sp = (void*) gsp->args[1];
		return 1;
	}
	return 0;
#endif
}

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
extern inline void
do_syscall_and_resume(struct generic_syscall *sys)
__attribute__((always_inline,gnu_inline));

extern inline long int
do_real_syscall(struct generic_syscall *sys)
__attribute__((always_inline,gnu_inline));

extern inline void
__attribute__((always_inline,gnu_inline))
do_generic_syscall_and_resume(struct generic_syscall *gsp)
{
	void *new_top_of_stack = NULL;
	_Bool stack_may_be_zapped = zaps_stack(gsp, &new_top_of_stack);

	/* FIXME: on i386, the effective trap_len is either
	 * 2 (normally)
	 * or
	 * 2 + some delta, if our trap site is the 'sysenter' inside the
	 * vDSO.
	 * We detect specially the case where we have a real_sysinfo, a fake_sysinfo,
	 * a sysenter_offset_in_real_sysinfo,
	 * and the trap site.
	 * We fix it up to the first 'nop' after an int 0x80 following the sysenter.
	 * This is a hack. In principle, the actual resume address is entirely private
	 * to the kernel. But it seems to work by immediately following the sysenter
	 * with an int 0x80 and pretending that the user context is that int 0x80.
	 * So, to the rest of the kernel it looks like that int 0x80 is what caused
	 * the syscall. See linux's arch/x86/entry/vdso/vma.c... my reading is that the
	 * the never-used int 0x80 instruction bytes are called the 'landing pad'.
	 *
	 * FIXME: actually implement this delta. Weirdly we seem no longer to witness
	 * the double-trap that was a problem earlier (spurious second syscall with %eax
	 * equal to the return value of the previous syscall). Debug this. Maybe we're
	 * just not taking traps from the fake vDSO any more? That's one of the last things
	 * I fiddled with. But I am seeing exit_group().
	 *
	 * OH. It's because we only do *one* such syscall, and GAHAHAHAH. My test case
	 * is exit, which just does exit_group().
	 */

	register long ret;
	if (!stack_may_be_zapped)
	{
		ret = do_real_syscall(gsp);            /* always inlined */
		fixup_sigframe_for_return(gsp->saved_context, ret,
			trap_len(&gsp->saved_context->uc.uc_mcontext), NULL);
		__systrap_post_handling(gsp, ret, /* do_caller_fixup */ 0);
		return;
	}

#if defined(__x86_64__)
#define STACK_ALIGN 16
#elif defined(__i386__)
#define STACK_ALIGN 4
#else
#error "Unsupported architecture."
#endif
	assert(new_top_of_stack);
	// we should have a new top of stack
	assert(gsp->args[1] /* a.k.a. 'stack' argument to raw clone() syscall */);
	// our new stack should be aligned
	assert(0 == (uintptr_t) new_top_of_stack % STACK_ALIGN);
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
	void *swizzled_bp = NULL; // see below -- this is bp as rewritten to point within the *new* stack
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
__  X|________|<-- sp at clone() site                 Y.________ <--stack limit! == new_top_of_stack
 ^^  | . . .  |\                                       | . . .  |\
 ||  |  . . . | sigframe stuff                         |  . . . | COPY of sigframe stuff
Z||Z'|________|/    incl. saved ip = clone site (1)    |________|/    incl saved ip = clone site (AGAIN; YES)
 |v  | . . .  |\ us a.k.a. handle_sigill               | . . .  |\  COPY of us
 v___|__-_-_-_|/ <-- sp at time of syscall             |__-_-_-_|/ <-- hacked sp we gave to clone()

                      ... the - - -  data might not be copied so had better not be important!

	 * The idea is that after sigreturn in the child, sp == new_top_of_stack (Y)
	 * and ip == the instruction after the trapping clone (i.e. same as in the parent).
	 *
	 * Q. How do we fix up the rip?
	 * A. We don't! The raw clone does not take a new code address.
	 *    Instead it's the job of the surrounding code, executing in the
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
	 *        code because the compiler may adjust the stack pointer. Instead we calculate
	 *        it only in inline asm, having left a useful breadcrumb B.
	 *
	 *        B = Y-X
	 *
	 *    and then we add X-Z, i.e. the current SP, when we are in the inline assembly,
	 *    to set the new stack argument to its final desired value of Y-Z.
	 *
	 * PROBLEM: when we pre-copy the stack, we can only copy using an approximation of Z,
	 * which I have labelled Z' above. If any late adjustments to the calling SP allocate
	 * more stack storage, this will not be copied over. TODO: fix this by doing the copy
	 * in an out-of-line function that we call from the inline asm.
	 *
	 * PROBLEM: we would like Z to be 16-byte-aligned, as it would let us arrange
	 * that the the child SP is also 16-byte-aligned, which clone() *seems* to need (ASSUMPTION).
	 * We used to assert that our trap site's SP was 16-byte-aligned.
	 * That would make it easy to reason that our new stack value is aligned,
	 * if our old stack is. However, the assertion sometimes fails! It seems it
	 * is not a requirement, after all, on x86_64 Linux, that rsp be 16-byte-aligned
	 * on a system call. In any case, Z depends on how many stack slots the compiler uses...
	 * we can't ensure it will be 16-byte-aligned until we are into the inline assembly.
	 * So we use a variation of our AND-based stack alignment scheme. We probe for
	 * misalignment, and adjust argreg1 (the 'new stack' register) if needed, just for
	 * the clone(), then adjust it back afterwards. We can test the alignment using our
	 * breadcrumb B, i.e. we can check before or after we add back %rsp. NOTE that we don't
	 * also adjust %rsp. There's no need; the value of argreg1 matters only in the child.
	 * Also if we did adjust %rsp and *then* turned the breadcrumb back into the real new_sp,
	 * it would be misaligned again because this would amount to a double adjustment.
	 *
	 * If I do the misalign hack below, I still get a misaligned
	 * child stack, which is surprising.
	 * If also I omit to perform the stack alignment around the syscall,
	 * the dmesg prints out a message about a bad sigframe (in the child).
	 * So I've clearly broken something there too.
	 */

	/* Start of copy: our current sp, rounded up to the relevant alignment.
	 * XXX: aligning the stack pointer here is not useful, because (on x86_64)
	 * nothing stops the compiler from pushing an odd number of words between
	 * here and the clone. Really we have to align the stack downwards and
	 * remember how much we aligned it by, and then do the reverse afterwards. */
	uintptr_t *copysrc_start = (uintptr_t*) ROUND_UP_PTR(STACK_ALIGN, (uintptr_t) orig_sp);
	/* The saved syscall context's esp, which it expects to be zapped.
	 * Anything here or earlier on the stack is irrelevant post-zap. */
	uintptr_t *copysrc_end = (uintptr_t*) (gsp->saved_context->uc.uc_mcontext.MC_REG_SP);

	/* Sanity: we expect the syscall ctxt block to be on *this* stack, so above current esp.
	 * FIXME: tighter check, and hard-abort if it fails (even when NDEBUG). */
	assert((uintptr_t) gsp > (uintptr_t) copysrc_start);
	/* Sanity: the block runs in the direction we expect, i.e. upwards */
	assert((uintptr_t) copysrc_end > (uintptr_t) copysrc_start);
	/* Sanity: we are not copying implausibly much. */
	assert((uintptr_t) copysrc_end - (uintptr_t) copysrc_start < 0x10000u);
	size_t length_of_stack_to_copy = copysrc_end - copysrc_start;

	uintptr_t *copydest_start = (uintptr_t *) new_top_of_stack - length_of_stack_to_copy;
	uintptr_t *p_dest = copydest_start;
	long fixup_delta = (uintptr_t) p_dest - (uintptr_t) copysrc_start;
	unsigned nbytes = (uintptr_t) copysrc_end - (uintptr_t) copysrc_start;
	/* We shouldn't be copying more than a page (-epsilon) of stuff, because
	 * we can't know that the cloning code has allocated more stack than that. */
	assert(nbytes < MIN_PAGE_SIZE - sizeof (void*));
	memcpy(p_dest, copysrc_start, nbytes);
	for (uintptr_t *p_src = copysrc_start; p_src != copysrc_end; ++p_src, ++p_dest)
	{
		// *p_dest = *p_src;
		/* Relocate any word we copy if it's a stack address. HMM.
		 * I suppose we don't use any large integers that aren't addresses?
		 * We should really walk this buffer like it's a real stack, and
		 * fix up only saved sp/bp values. Perhaps __builtin_frame_address
		 * is useful here? */
		if (*p_src < (uintptr_t) copysrc_end && *p_src >= (uintptr_t) copysrc_start)
		{
			// fixup_delta is defined by the equation:
			// srcval + fixup_delta = destval
			uintptr_t existing_word = *p_src;
			uintptr_t new_word = existing_word + fixup_delta;
			*p_dest = new_word;
			/* To what value do we need to swizzle the BP?
			 * Here we take the lowest-addressed stored pointer in need of fixup...
			 * we just take its fixed-up value.
			 * That seems fragile and perhaps wrong.
			 *
			 * Surely we know the delta directly?
			 * There are TWO deltas.
			 * One is the inter-stack distance, fixup_delta.
			 *
			 * Another is the intra-stack distance,
			 * i.e. from new_sp (high) to
			 * the place where we set the stack when we actually resume (lower)
			 *
			 * ebp is the stack pointer stored at the lowest address on the
			 * current stack. Oh, wait. I think we are changing that
			 * in this code. In fact so is p_src... also such a pointer. */
			if (!swizzled_bp)
			{
				swizzled_bp = (void*)(*p_dest); // MONSTER HACK
				// REMEMBER this hack was necessary because if we read ebp in this
				// function, or use __builtin_frame_address,
				// GCC refuses to solve our ASM constraints.
				// BREAK debugger here and check that BP matches (uintptr_t) new_word - fixup_delta
			}
		}
	}
	swizzled_bp = (void*)((uintptr_t) orig_bp + fixup_delta);
	assert(swizzled_bp);
	assert((uintptr_t) swizzled_bp < (uintptr_t) new_top_of_stack);
	assert((uintptr_t) swizzled_bp >= (uintptr_t) copydest_start);
	/* After the syscall we'll be using the new stack ourselves for a bit. So
	 * initially we need the SP somewhat below the actual requested user SP. Then
	 * it'll get popped back to the SP the user really wanted. (CARE about stack
	 * growth direction: it grows to lower addresses, but we copied low-to-high.)
	 *
	 * PROBLEM: how far below? We can only compute it now assuming that our
	 * SP doesn't change between here and the syscall site, i.e. is still copysrc_start.
	 * But it might change!
	 *
	 * Put differently, we want to write

	long int intra_stack_fixup =
		gsp->saved_context->uc.uc_mcontext.MC_REG_SP // The (higher) stack pointer at the trap site
			-
		CURRENT_SP                    //The (low) stack pointer as we have it, %[er]sp
	;
	gsp->args[1] -= intra_stack_fixup; // subtract a positive number

	 * but that's not robust, because sp might change (copysrc_start isn't reliable,
	 * i.e. we have no CURRENT_SP as we would like it above).
	 * CURRENT_SP could be called "parent_sp_at_syscall_time".
	 *
	 * Instead, we put something 'fake' in gsp->args[1]
	 * that we then *add/subtract SP* during the inline assembly.
	 * During the inline assembly, we are in control of the stack pointer
	 * all the way up to the syscall site.
	 *
	 * What is the fake thing we put there? In short, it's the real new SP we want
	 * *minus* the stack pointer at the time of the syscall. These are on different
	 * stacks, so this could be a really wacky number!
	 *
	 * Let's call 'syscall_arg1' the new SP we really want in the child. We know:
	 *
	 * syscall_arg1 = new_sp_on_resume - (parent_sp_at_trap - parent_sp_at_syscall_time)
	 *
	 * and we want to set fake_arg1 s.t. we can add the stack pointer to it. We know:
	 *
	 * fake_arg1 + parent_sp_at_syscall_time = syscall_arg1       # we will add SP to the fake
	 *
	 * so
	 *
	 * fake_arg1 = syscall_arg1 - parent_sp_at_syscall_time
	 * fake_arg1 = new_sp_on_resume - (parent_sp_at_trap - parent_sp_at_syscall_time) - parent_sp_at_syscall_time
	 * fake_arg1 = new_sp_on_resume - parent_sp_at_trap
	 *
	 * Q. Where do we pull this fake value out of gsp->args[1]?
	 * A. in the use of %[arg1] below... we mov it in the argreg.
	 * 
	 * NOTE: we are ONLY updating the copy on the PARENT on-stack gsp.
	 *
	 * When we resume from our sigframe in the child, and pass our
	 * new stack pointer (see below), we do NOT need to perform
	 * the reverse adjustment.
	 * WHY NOT? I had written:
	 * "In the child, the copy we took above of gsp->args[1], as part of
	 * our memcpy, was correctly fixed up to point into the new stack."
	 * XXX: was it? If we could do that, why do we need this fakery?
	 * XXX: perhaps this copy could be wrong, but it just doesn't get used?
	 * Although we do copy the gsp onto the new stack, we don't use its arg
	 * values on the resume path... only pretcode I think.
	 */
	// FIXME: should have used 'unsigned int'
	//*(uintptr_t *)(&gsp->args[1]) -= (uintptr_t) gsp->saved_context->uc.uc_mcontext.MC_REG_SP;
	uintptr_t breadcrumb = (uintptr_t) gsp->args[1] - (uintptr_t) gsp->saved_context->uc.uc_mcontext.MC_REG_SP;

	/* We have to use one big asm in order to keep stuff
	 * in registers long enough to call our helper.
	 *
	 * The basic idea is that everything we might need, if
	 * our stack gets zapped, is copied to the *new* stack
	 * and addressed via gsp.
	 *
	 * Then, the gsp within the new stack is the only thing
	 * we need to hold on to. Get everything else from that!
	 * For example the fixed-up stack pointer is stored within
	 * the gsp structure.
	 *
	 * On 32-bit x86, how do we want this to work?
	 * We have to use %ebp which is the only spare register.
	 * But logically we have both 'delta' and 'gsp' to transfer.
	 * We solve this by calculating the swizzled (new-stack) ebp.
	 * We eagerly put this in %ebp for the call, having pushed
	 * the old value. If we zapped the stack, then we now have a
	 * new stack and %ebp is pointing correctly into that.
	 * If we didn't zap the stack, we restore the old %ebp by popping.
	 */
	long int ret_op = (long int) gsp->syscall_number;
	__asm__ volatile (
		  "mov %[arg0], %%"stringifx(argreg0)" \n\
		   mov %[arg1], %%"stringifx(argreg1)" \n\
		   mov %[arg2], %%"stringifx(argreg2)" \n\
		   mov %[arg3], %%"stringifx(argreg3)" \n\
		   mov %[arg4], %%"stringifx(argreg4)"  \n"
	#if defined(__x86_64__)
		  "push %%rbp                           # we will restore the old BP in the parent... \n\
		   mov %[swizzled_bp], %%rbp            # ... but use this swizzled one in the child \n"
		   /* begin PERFORM_SYSCALL replacement */
		  "add %%rsp,  %%"stringifx(argreg1)" \n" /* make non-fake arg1 out of fake one...
		    By now, argreg1 is either 
		       - new_stack - Z - 8     (if Z is congruent to 8 modulo 16)  or
		       - new_stack - Z         (if Z divides by 16)
		    ... and in the first case, we will immediately add back the 8 on the child side
		    so that the child %rsp == new_stack - Z
		    where Z is exactly the number of bytes that will be popped off the stack on the
		    journey though the remainder of this function and the sigreturn.
		    GAH. Not quite.
		    What if %rsp is congruent to 8? Then argreg1 is no longer divisible by 16!
		    Oh, OK. We need to do the adjustment after the breadcrumb fix.
		 */
		  "movq %%"stringifx(argreg1)", %%r12 \n\
		   andq $0xf, %%r12                     # now we have either 8 or 0 in r12 \n"
		  "subq %%r12, %%"stringifx(argreg1)"   # fix the *new* stack pointer \n"
		   stringifx(SYSCALL_INSTR) "\n"
		   /* end PERFORM_SYSCALL replacement */
		   /* Immediately test: did our stack actually get zapped? */
		   "cmpq %%rsp, %%"stringifx(argreg1)"\n"
		   "je .L001$           # if taken, it means we are the child with a new stack \n"
		   /* When we take the 'je' above, to .001 below, our old stack is gone.
		    * We've already put swizzled_bp in ebp/rbp where it belongs. The compiler-generated
		    * code in both parent and child may still need the BP to refer to locals, which is
		    * why we swizzled it.*/
		   "pop %%rbp           # restore the correct BP \n"
		   "jmp .L002$ \n"
		".L001$:\n"
		   "addq %%r12, %%rsp   # undo the 16-byte alignment fix we applied earlier, if any (value now in SP, not argreg1!) \n"
		   "addq $0x8, %%rsp    # discard the unwanted saved BP (actually uninitialized/zero in the child) \n"
		   "jmp .L002$ \n"
	#elif defined(__i386__)
		  "push %%ebp\n\
		   mov %[swizzled_bp], %%ebp \n"
		  "add %%esp,   %%"stringifx(argreg1)" \n"  /* make non-fake arg1 out of fake one */
		   /* begin PERFORM_SYSCALL expansion */
		   stringifx(SYSCALL_INSTR) "\n"
		   /* end PERFORM_SYSCALL expansion */
		   /* Immediately test: did our stack actually get zapped? */
		   "cmpl %%esp, %%"stringifx(argreg1)"\n"
		   "je .L001$ \n"
		   "pop %%ebp\n"
		   "jmp .L002$ \n"
		".L001$:\n"
		   "nop \n"
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
		  : [swizzled_bp] "m" (swizzled_bp)        /* swizzled_bp is an input */
		  , [arg0] "m" ((long int) gsp->args[0])
		  , [arg1] "m" (/*(long int) gsp->args[1]*/ breadcrumb)
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
	fixup_sigframe_for_return(gsp->saved_context, /*new_top_of_stack - sizeof (struct ibcs_sigframe), */
		ret_op, trap_len(&gsp->saved_context->uc.uc_mcontext),
		/* new_sp: we have a new sp only if we're the child.
		 * We can detect that using ret_op i.e. clone()'s return value. */
		(ret_op == 0) ? (void*) (gsp->args[1] /* see fake_arg1 comment above  */)
			: NULL);
	__systrap_post_handling(gsp, ret_op, /* do_caller_fixup */ 0);
}

extern inline void 
__attribute__((always_inline,gnu_inline))
do_syscall_and_resume(struct generic_syscall *gsp)
{
	/* This is our general function for performing or emulating a system call.
	 * If the syscall does not have a replacement installed, we follow a generic
	 * emulation path.
	 *
	 * The 'post_handling' argument is worth explaining.
	 * A typical replad_syscalls function looks like this.

	void frob_replacement(struct generic_syscall *s, post_handler *post)
	{
        	// Unpack the arguments.
        	void *old_addr = (void*) s->args[0];
        	...
        	// Do the call we actually want to do
        	void *ret = raw_frob(old_addr ^ 0x42);
        	// Do the post-handling and resume.
        	post(s, (long) ret, 1); //<------- means YES PLEASE FIXUP THE SIGFRAME
                                	// i.e. "we did not fix it up ourselves, lazy lazy"
	}

	 * Our SIGILL handler will always pass the "post_handler" because each
	 * application of our library may have some generic post-syscall stuff to do.
	 * So, post-handling is shared with the "default emulation path", when
	 * there is no replacement syscall, and the "replaced" path.
	 * We tell the post-handler whether it's necessary to do the sigframe
	 * fixup.
	 * XXX: is this flexibility really needed? Are there any applications which
	 * want to replace a syscall while doing their own fixup, so would pass 0 not
	 * 1 above? Are there any emulation paths where we *do* want the
	 * post-handler to do the fixup, i.e. we would pass 1 here?
	 *
	 * If not, then we could simplify this. E.g. why not have replacement syscalls
	 * return to their caller? Am I right that the post_handler is noreturn?
	 *
	 */
	systrap_pre_handling(gsp);
	if (replaced_syscalls[gsp->syscall_number])
	{
		/* Since replaced_syscalls holds function pointers, these calls will 
		 * not be inlined. It follows that if the call ends up doing a real
		 * clone(), we have no way to get back here. So the semantics of a 
		 * replaced syscall must include "do your own resumption". We therefore
		 * pass the post-handling as a function. */
		replaced_syscalls[gsp->syscall_number](gsp, &__systrap_post_handling);
	}
	else
	{
		do_generic_syscall_and_resume(gsp);
	}
}

extern inline long int 
__attribute__((always_inline,gnu_inline))
do_real_syscall (struct generic_syscall *gsp) 
{
	return do_syscall6(gsp);
}

#endif
