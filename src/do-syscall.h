#ifndef DO_SYSCALL_H_
#define DO_SYSCALL_H_

#include "raw-syscalls-impl.h" /* always include raw-syscalls first, and let it do the asm includes */

#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
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
 * we swizzle the gsp to the one we copied onto the new stack.
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

	assert(new_top_of_stack);
	// we should have a new top of stack
	assert(gsp->args[1]);
	// everything we need gets copied
	/* We want to initialize the new stack. Then we will have to fix up
	 * rsp immediately after return, then jump straight to pretcode,
	 * which does the sigret. Will it work? Yes, it seems to. */
	uintptr_t *cur_stack_low;
	void *swizzled_bp = NULL; // see below
#if defined(__x86_64__)
	__asm__ volatile ("movq %%rsp, %0" : "=rm"(cur_stack_low) : : );
#elif defined(__i386__)
	__asm__ volatile ("movl %%esp, %0" : "=rm"(cur_stack_low) : : );
#else
#error "Unsupported architecture."
#endif
	/* There may be stuff on the sigframe above the struct ibcs_sigframe.
	 * We use the saved esp to work out how much to copy.
	 * The idea is that after sigreturn, esp == new_top_of_stack
	 * and eip == the instruction after the trapping clone. */
	uintptr_t *p_src_end = (uintptr_t*) (gsp->saved_context->uc.uc_mcontext.MC_REG_SP);

	assert((uintptr_t) gsp > (uintptr_t) cur_stack_low);
	assert((uintptr_t) p_src_end > (uintptr_t) cur_stack_low);
	assert((uintptr_t) p_src_end - (uintptr_t) cur_stack_low < 0x10000u);
	uintptr_t *p_dest_start = (uintptr_t *) new_top_of_stack - (p_src_end - cur_stack_low);
	uintptr_t *p_dest = p_dest_start;
	long delta_nbytes = (uintptr_t) p_dest - (uintptr_t) cur_stack_low;
	/* FIXME: check we are still in bounds of the new stack. I guess it
	 * should be doing MAP_GROWSDOWN...? But maybe we need to copy in
	 * reverse order? */
	for (uintptr_t *p_src = cur_stack_low; p_src != p_src_end; ++p_src, ++p_dest)
	{
		*p_dest = *p_src;
		/* Relocate any word we copy if it's a stack address. HMM.
		 * I suppose we don't use any large integers that aren't addresses?
		 * We should really walk this buffer like it's a real stack, and
		 * fix up only saved sp/bp values. Perhaps __builtin_frame_address
		 * is useful here? */
		if (*p_src < (uintptr_t) p_src_end && *p_src >= (uintptr_t) cur_stack_low)
		{
			// delta_nbytes is defined by the equation:
			// srcval + delta_nbytes = destval
			*p_dest += delta_nbytes;
			/* ebp is the stack pointer stored at the lowest address on the
			 * current stack. Oh, wait. I think we are changing that
			 * in this code. In fact so is p_src... also such a pointer. */
			if (!swizzled_bp) swizzled_bp = (void*)(*p_dest); // MONSTER HACK
		}
	}
	assert(swizzled_bp);
	assert((uintptr_t) swizzled_bp < (uintptr_t) new_top_of_stack);
	assert((uintptr_t) swizzled_bp >= (uintptr_t) p_dest_start);
	/* After the syscall we're already using the new stack, so make it right. */
	gsp->args[1] = (uintptr_t)(void*)(p_dest - 1);
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
	// struct generic_syscall *swizzled_gsp = (struct generic_syscall *)((uintptr_t) gsp + delta_nbytes);
	//void *swizzled_bp = (struct generic_syscall *)((uintptr_t) gsp + delta_nbytes);
	/* To get %ebp and then swizzle it, one would think
	 * we could simply use inline asm, or
	 * we could maybe use __builtin_frame_address(0).
	 * However, if we use either of these
	 * here, GCC will deem our constraints later to be insoluble.
	 * At first I thought it was snooping on our use of %ebp/%rbp in
	 * assembly. But that's not the case... it is happy with our clobber/
	 * restore of %ebp in the assembly below. I even tried raw binary
	 * instructions to disguise access to %ebp/%rbp, to no avail.
	 * It seems the problem is triggered if swizzled_bp is the output of
	 * *any* asm or builtin, even 'nop' like this.
	 *__asm__ ("nop" : "=r"(swizzled_bp) : : );
	 * We work around this in a very sneaky way. Our current
	 * %ebp is a fixed offset from the lowest stack address currently
	 * saved on the stack (assuming none of our locals points to a local).
	 * So when we do a copy-and-relocate of the stack (above), we
	 * snarf the first pointer we relocate.*/

	__asm__ volatile (
		  "mov %[arg0], %%"stringifx(argreg0)" \n\
		   mov %[arg1], %%"stringifx(argreg1)" \n\
		   mov %[arg2], %%"stringifx(argreg2)" \n\
		   mov %[arg3], %%"stringifx(argreg3)" \n\
		   mov %[arg4], %%"stringifx(argreg4)"  \n"
	#if defined(__x86_64__)
		  "push %%rbp\n\
		   mov %[swizzled_bp], %%rbp \n"
		   PERFORM_SYSCALL
		   /* Immediately test: did our stack actually get zapped? */
		   /* FIXME: what about UNFIX_STACK_ALIGNMENT messing with %rsp? */
		   "cmpq %%rsp, %%"stringifx(argreg1)"\n"
		   "je .L001$ \n" // FIXME make temporary label
		   "pop %%rbp\n"
	#elif defined(__i386__)
		  "push %%ebp\n\
		   mov %[swizzled_bp], %%ebp \n"
		   PERFORM_SYSCALL
		   /* Immediately test: did our stack actually get zapped? */
		   "cmpl %%esp, %%"stringifx(argreg1)"\n"
		   "je .L001$ \n" // FIXME make temporary label
		   /* When we take this jump, our old stack is gone. We've already put swizzled_bp
		    * in ebp where it belongs. */
		   /* There is no need to pop the saved %ebp; our old stack is really gone!
		    * But note that the compiler-generated code may still need %ebp,
		    * to refer to our locals. That's why we swizzled it.
		    * It should also be the case that our new gsp equals the old gsp plus delta_nbytes.
		    * But we can't assert that because we no longer have the old gsp.
		    *
		    * We list gsp it as a memory output so that the compiler thinks it's
		    * clobbered. That way, it will keep it in its stack slot during the asm block,
		    * and will reload it later if it's needed in a register. Of course it
		    * will be reloading the new, swizzled version, but that is all transparent
		    * to the compiler. */
		   /* The swizzled bp is critical, because if we're the child:
		    *
		    * (1) we can't safely use anything that might have been spilled to the old stack.
		    *
		    * (2 we can't look at the old sigframe, even via its absolute ptr, because
		    *    the other thread might have finished with it and cleaned up.
		    *
		    * Instead, use the copy we put in the new stack. This is all hidden from
		    * the compiler, who thinks we haven't touched our bp.
		    *
		    * So the following code should work automagically through our swizzled ebp, since
		    * that's where we get our locals, including gsp. That, in turn, was swizzled
		    * above when we copied the stack.
		    */
		   "pop %%ebp\n"
	#else
	#error "Unsupported architecture."
	#endif
		".L001$:\n"
		   "nop\n"
		  : [ret]  "+a" (ret_op), [gsp] "=m"(gsp)  /* gsp is a fake output, i.e. a clobber */
		  : [swizzled_bp] "m" (swizzled_bp)        /* swizzled_bp is an input */
		  , [arg0] "m" ((long int) gsp->args[0])
		  , [arg1] "m" ((long int) gsp->args[1])
		  , [arg2] "m" ((long int) gsp->args[2])
		  , [arg3] "m" ((long int) gsp->args[3])
		  , [arg4] "m" ((long int) gsp->args[4])
		  : "%"stringifx(argreg0), "%"stringifx(argreg1), "%"stringifx(argreg2),
		    "%"stringifx(argreg3), "%"stringifx(argreg4), DO_SYSCALL_CLOBBER_LIST(5)
	);
	// FIXME: can we do this fixup before the clone, but
	// after the stack copy. We just fix up the copied context
	// on the stack, speculatively. Might be cleaner and fit with our
	// "walk the stack and fix up saved BPs only" idea, i.e. minimise
	// how many on-stack pointers have to work to get us to the sigreturn.
	fixup_sigframe_for_return(gsp->saved_context, /*new_top_of_stack - sizeof (struct ibcs_sigframe), */
		ret_op, trap_len(&gsp->saved_context->uc.uc_mcontext),
		/* new_sp: we have a new sp only if we're the child.
		 * We can detect that using ret_op i.e. clone()'s return value. */
		(ret_op == 0) ? (void*) gsp->args[1] : NULL);
	__systrap_post_handling(gsp, ret_op, /* do_caller_fixup */ 0);
}

/* This is our general function for performing or emulating a system call.
 * If the syscall does not have a replacement installed, we follow a generic
 * emulation path. Unfortunately this is BROKEN for clone() at the moment,
 * because we can't reliably tell the compiler not to use the stack...
 * we need to rewrite that path in assembly. */
extern inline void 
__attribute__((always_inline,gnu_inline))
do_syscall_and_resume(struct generic_syscall *gsp)
{
	/* How can we post-handle a syscall after the stack is zapped by clone()?
	 * Actually it's very easy. We can still call down. We just can't return. */
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
