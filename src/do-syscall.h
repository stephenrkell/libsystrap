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

extern inline _Bool 
__attribute__((always_inline,gnu_inline))
zaps_stack(struct generic_syscall *gs);

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
	  : DO_SYSCALL_CLOBBER_LIST);

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
	  : "%"stringifx(argreg0), DO_SYSCALL_CLOBBER_LIST);

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
	  : "%"stringifx(argreg0), "%"stringifx(argreg1), DO_SYSCALL_CLOBBER_LIST);

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
	  : "%"stringifx(argreg0), "%"stringifx(argreg1), "%"stringifx(argreg2), DO_SYSCALL_CLOBBER_LIST);

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
	  : "%"stringifx(argreg0), "%"stringifx(argreg1), "%"stringifx(argreg2), "%"stringifx(argreg3), DO_SYSCALL_CLOBBER_LIST);

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
	  : "%"stringifx(argreg0), "%"stringifx(argreg1), "%"stringifx(argreg2), "%"stringifx(argreg3), "%"stringifx(argreg4), DO_SYSCALL_CLOBBER_LIST);

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
			   mov %[arg5], %%"stringifx(argreg5)" \n"
			   PERFORM_SYSCALL
	  : [ret]  "+a" (ret_op)
	  : [arg0] "rm" ((long int) gsp->args[0])
	  , [arg1] "rm" ((long int) gsp->args[1])
	  , [arg2] "rm" ((long int) gsp->args[2])
	  , [arg3] "rm" ((long int) gsp->args[3])
	  , [arg4] "rm" ((long int) gsp->args[4])
	  , [arg5] "rm" ((long int) gsp->args[5])
	  : "%"stringifx(argreg0), "%"stringifx(argreg1), "%"stringifx(argreg2), "%"stringifx(argreg3), "%"stringifx(argreg4), /*"%"stringifx(argreg5),*/ DO_SYSCALL_CLOBBER_LIST);
	return ret_op;
}


/* These must be inline and noreturn because we can't rely on the on-stack return
 * address being there after the syscall. In particular, clone() will leave us with
 * a zero-filled stack. So everything we need to resume the caller must be in registers.
 * Note that we can use stack locals. But we can't rely on stack locals *before* the 
 * syscall still being there afterwards. */
extern inline void
do_syscall_and_resume(struct generic_syscall *sys)
__attribute__((always_inline,gnu_inline));

extern inline long int 
do_real_syscall(struct generic_syscall *sys)
__attribute__((always_inline,gnu_inline));

extern inline void
__attribute__((always_inline,gnu_inline))
fixup_caller_for_return(long int ret, struct ibcs_sigframe *p_frame, unsigned instr_len)
{
	/* Copy the return value of the emulated syscall into the trapping context, and
	 * resume from *after* the faulting instruction. 
	 * 
	 * Writing through p_frame is undefined behaviour in C, or at least, gcc optimises 
	 * it away for me. So do it in volatile assembly. */

	// set the return value
	// HACK: it's in the same place as the syscall number
	__asm__ volatile ("mov %1, %0" : "=m"(p_frame->uc.uc_mcontext.MC_REG(syscallnumreg, SYSCALLNUMREG)) : "r"(ret) : "memory");

	// adjust the saved program counter to point past the trapping instr
	__asm__ volatile ("mov %1, %0" : "=m"(p_frame->uc.uc_mcontext.MC_REG_IP) : "r"(p_frame->uc.uc_mcontext.MC_REG_IP + instr_len) : "memory");
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
		/* HACK: these must not be spilled to the stack at the point where the 
		 * syscall occurs, or they may be lost.
		 * HACK EVEN MORE: this code doesn't work right now  */
		register _Bool stack_zapped /*__asm__ ("rbx")*/ = zaps_stack(gsp);
		register uintptr_t *new_top_of_stack /*__asm__ ("rcx")*/ = (uintptr_t *) gsp->args[1];
		register uintptr_t *new_sp /*__asm__ ("rdx")*/ = 0;
		
		if (stack_zapped)
		{
			assert(new_top_of_stack);
			
			/* We want to initialize the new stack. Then we will have to fix up 
			 * rsp immediately after return, then jump straight to pretcode,
			 * which does the sigret. Will it work? Yes, it seems to. */
			
			uintptr_t *stack_copy_low;
#if defined(__x86_64__)
			__asm__ volatile ("movq %%rsp, %0" : "=rm"(stack_copy_low) : : );
#elif defined(__i386__)
			__asm__ volatile ("movl %%esp, %0" : "=rm"(stack_copy_low) : : );
#else
#error "Unsupported architecture."
#endif
			
			uintptr_t *stack_copy_high
			 = (uintptr_t *)((char*) gsp->saved_context + sizeof (struct ibcs_sigframe));
			
			unsigned copy_nwords = stack_copy_high - stack_copy_low;
			uintptr_t *new_stack_lowaddr = new_top_of_stack - copy_nwords;
			ptrdiff_t fixup_amount = (char*) new_stack_lowaddr - (char*) stack_copy_low;
			for (unsigned i = 0; i < copy_nwords; ++i)
			{
				new_stack_lowaddr[i] = stack_copy_low[i];
				/* Relocate any word we copy if it's a stack address. HMM.
				 * I suppose we don't use any large integers that aren't addresses? */
				if (new_stack_lowaddr[i] < (uintptr_t) stack_copy_high
							&& new_stack_lowaddr[i] >= (uintptr_t) stack_copy_low)
				{
					new_stack_lowaddr[i] += fixup_amount;
				}
			}
			new_sp = new_stack_lowaddr; // (uintptr_t) ((char *) stack_copy_low + fixup_amount);
		}
		
		register unsigned trap_len /*__asm__ ("rsi")*/ = instr_len(
			(unsigned char*) gsp->saved_context->uc.uc_mcontext.MC_REG_IP,
			(unsigned char*) -1 /* we don't know where the end of the mapping is */
			);
		
		struct generic_syscall *copied_gsp = alloca(sizeof (struct generic_syscall));
		// HACK: avoid string.h dependency (causes __locale_t problems)
		__builtin_memcpy(copied_gsp, gsp, sizeof *gsp);
		
		long int ret = do_real_syscall(gsp);            /* always inlined */
		/* Did our stack actually get zapped? */
		if (stack_zapped)
		{
			uintptr_t *seen_sp;
#if defined(__x86_64__)
			__asm__ volatile ("movq %%rsp, %0" : "=r"(seen_sp) : : );
#elif defined(__i386__)
			__asm__ volatile ("mov %%esp, %0" : "=r"(seen_sp) : : );
#else
#error "Unsupported architecture."
#endif
			stack_zapped &= (seen_sp == new_top_of_stack);
		}
		
		/* At this point, if we're the child:
		 * 
		 * (1) we can't safely use anything that might have been spilled to the stack. 
		 * 
		 * (2 we can't look at the old sigframe, even via its absolute ptr, because 
		 *    the other thread might have finished with it and cleaned up.
		 *    Instead, use the copy we put in the new stack.
		 */
		
		/* FIXME: how to ensure that the compiler doesn't spill something earlier and 
		 * re-load it here? Ideally we need to rewrite this whole function in assembly. 
		 * We could make fixup_caller_for_return a macro expanding to an asm volatile.... */
		
		__systrap_post_handling(copied_gsp, ret, !stack_zapped); /* okay, because we have a stack (perhaps zeroed/new) */
		/* FIXME: unsafe to access gsp here! Take a copy of *gsp! */
		if (stack_zapped)
		{
			/* We copied the context into the new stack. So just resume from sigframe
			 * as before, with two minor alterations. Firstly, the caller expects to
			 * resume with the new top-of-stack in rsp. Secondly, we fix up the current rsp
			 * so that the compiler-generated code will find its way to restore_rt 
			 * (i.e. that the function epilogue will use our new stack, not the old one). */

			struct ibcs_sigframe *p_frame = (struct ibcs_sigframe *) ((char*) new_top_of_stack - sizeof (struct ibcs_sigframe));
			/* Make sure that the new stack pointer is the one returned to the caller. */
#if defined(__x86_64__)
			p_frame->uc.uc_mcontext.MC_REG(rsp, RSP) = (uintptr_t) new_top_of_stack;
#elif defined(__i386__)
			p_frame->uc.uc_mcontext.MC_REG(esp, ESP) = (uintptr_t) new_top_of_stack;
#else
#error "Unsupported architecture"
#endif
			/* Do the usual manipulations of saved context, to return and resume from the syscall. */
			fixup_caller_for_return(ret, p_frame, trap_len);
			/* Hack our rsp so that the epilogue / sigret will execute correctly. */
#if defined(__x86_64__)
			__asm__ volatile ("movq %0, %%rsp" : /* no outputs */ : "r"(new_sp) : "%rsp");
#elif defined(__i386__)
			__asm__ volatile ("mov %0, %%esp" : /* no outputs */ : "r"(new_sp) : "%esp");
#else
#error "Unsupported architecture"
#endif
		}
	}
}

extern inline long int 
__attribute__((always_inline,gnu_inline))
do_real_syscall (struct generic_syscall *gsp) 
{
	return do_syscall6(gsp);
}

/* HACK: sysdep */
extern inline _Bool 
__attribute__((always_inline,gnu_inline))
zaps_stack(struct generic_syscall *gsp)
{
#ifdef __FreeBSD__
	return 0;
#else
	return gsp->syscall_number == __NR_clone
				&& gsp->args[1] /* newstack */ != 0;
#endif
}

#endif
