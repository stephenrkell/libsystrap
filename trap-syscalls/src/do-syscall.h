#ifndef DO_SYSCALL_H_
#define DO_SYSCALL_H_

#include <stddef.h>
#include <asm/types.h>
#include <asm/posix_types.h>
#include <unistd.h>
#include <stdint.h>
#include <asm/signal.h>
#include <asm/sigcontext.h>
#include <asm/siginfo.h>
#include <asm/ucontext.h>
#include <sys/syscall.h>

#include "raw-syscalls.h"
#include "syscall-names.h" /* for SYSCALL_MAX */
#include "instr.h"

extern _Bool __write_footprints;
extern uintptr_t our_load_address;

/* In kernel-speak this is a "struct sigframe" / "struct rt_sigframe" --
 * sadly no user-level header defines it. But it seems to be vaguely standard
 * per-architecture (here Intel iBCS). */
struct ibcs_sigframe
{
	char *pretcode;
	struct ucontext uc;
	struct siginfo info;
};

struct generic_syscall {
	struct ibcs_sigframe *saved_context;
	int syscall_number;
	long int arg0;
	long int arg1;
	long int arg2;
	long int arg3;
	long int arg4;
	long int arg5;
};

typedef void post_handler(struct generic_syscall *s, long int ret);
typedef void (__attribute__((noreturn)) syscall_replacement)(
	struct generic_syscall *s, 
	post_handler *post
);

extern syscall_replacement *replaced_syscalls[SYSCALL_MAX];

extern inline _Bool 
__attribute__((always_inline,gnu_inline))
zaps_stack(struct generic_syscall *gs);

#define PERFORM_SYSCALL	     \
	  FIX_STACK_ALIGNMENT "   \n\
	  movq %[op], %%rax       \n\
	  syscall		 \n\
	 "UNFIX_STACK_ALIGNMENT " \n\
	  movq %%rax, %[ret]      \n"


void write_footprint(void *base, size_t len);
void pre_handling(struct generic_syscall *gsp);
void post_handling(struct generic_syscall *gsp, long int ret);

/*
 * The x86-64 syscall argument passing convention goes like this:
 * RAX: syscall_number
 * RDI: ARG0
 * RSI: ARG1
 * RDX: ARG2
 * R10: ARG3
 * R8:  ARG4
 * R9:  ARG5
 */
extern inline long int 
__attribute__((always_inline,gnu_inline))
do_syscall0(struct generic_syscall *gsp)
{
	long int ret;

	__asm__ volatile (PERFORM_SYSCALL
	  : [ret] "=r" (ret)
	  : [op]  "rm" ((long int) gsp->syscall_number)
	  : "r12", SYSCALL_CLOBBER_LIST);

	return ret;
}

extern inline long int
__attribute__((always_inline,gnu_inline))
do_syscall1(struct generic_syscall *gsp)
{
	long int ret;

	__asm__ volatile ("movq %[arg0], %%rdi \n"
			   PERFORM_SYSCALL
	  : [ret]  "=r" (ret)
	  : [op]   "rm" ((long int) gsp->syscall_number)
	  , [arg0] "rm" ((long int) gsp->arg0)
	  : "r12", SYSCALL_CLOBBER_LIST);

	return ret;
}

extern inline long int 
__attribute__((always_inline,gnu_inline))
do_syscall2(struct generic_syscall *gsp)
{
	long int ret;
	__asm__ volatile ("movq %[arg0], %%rdi \n\
			   movq %[arg1], %%rsi \n"
			   PERFORM_SYSCALL
	  : [ret]  "=r" (ret)
	  : [op]   "rm" ((long int) gsp->syscall_number)
	  , [arg0] "rm" ((long int) gsp->arg0)
	  , [arg1] "rm" ((long int) gsp->arg1)
	  : "r12", SYSCALL_CLOBBER_LIST);

	return ret;
}

extern inline long int 
__attribute__((always_inline,gnu_inline))
do_syscall3(struct generic_syscall *gsp)
{
	long int ret;
	__asm__ volatile ("movq %[arg0], %%rdi \n\
			   movq %[arg1], %%rsi \n\
			   movq %[arg2], %%rdx \n"
			   PERFORM_SYSCALL
	  : [ret]  "=r" (ret)
	  : [op]   "rm" ((long int) gsp->syscall_number)
	  , [arg0] "rm" ((long int) gsp->arg0)
	  , [arg1] "rm" ((long int) gsp->arg1)
	  , [arg2] "rm" ((long int) gsp->arg2)
	  : "r12", SYSCALL_CLOBBER_LIST);

	return ret;
}

extern inline long int
__attribute__((always_inline,gnu_inline)) 
do_syscall6(struct generic_syscall *gsp)
{
	long int ret;
	__asm__ volatile ("movq %[arg0], %%rdi \n\
			   movq %[arg1], %%rsi \n\
			   movq %[arg2], %%rdx \n\
			   movq %[arg3], %%r10 \n\
			   movq %[arg4], %%r8  \n\
			   movq %[arg5], %%r9  \n"
			   PERFORM_SYSCALL
	  : [ret]  "=r" (ret)
	  : [op]   "rm" ((long int) gsp->syscall_number)
	  , [arg0] "rm" ((long int) gsp->arg0)
	  , [arg1] "rm" ((long int) gsp->arg1)
	  , [arg2] "rm" ((long int) gsp->arg2)
	  , [arg3] "rm" ((long int) gsp->arg3)
	  , [arg4] "rm" ((long int) gsp->arg4)
	  , [arg5] "rm" ((long int) gsp->arg5)
	  : "r12", SYSCALL_CLOBBER_LIST);

	return ret;
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
resume_from_sigframe(long int ret, struct ibcs_sigframe *p_frame, unsigned instr_len)
{
	/* Copy the return value of the emulated syscall into the trapping context, and
	 * resume from *after* the faulting instruction. 
	 * 
	 * Writing through p_frame is undefined behaviour in C, or at least, gcc optimises 
	 * it away for me. So do it in volatile assembly. */

	// set the return value
	__asm__ volatile ("movq %1, %0" : "=m"(p_frame->uc.uc_mcontext.rax) : "r"(ret) : "memory");

	// adjust the saved program counter to point past the trapping instr
	__asm__ volatile ("movq %1, %0" : "=m"(p_frame->uc.uc_mcontext.rip) : "r"(p_frame->uc.uc_mcontext.rip + instr_len) : "memory");
}

extern inline void 
__attribute__((always_inline,gnu_inline))
do_syscall_and_resume(struct generic_syscall *gsp)
{
	/* How can we post-handle a syscall after the stack is zapped by clone()?
	 * Actually it's very easy. We can still call down. We just can't return. */
	pre_handling(gsp);
	if (replaced_syscalls[gsp->syscall_number])
	{
		/* Since replaced_syscalls holds function pointers, these calls will 
		 * not be inlined. It follows that if the call ends up doing a real
		 * clone(), we have no way to get back here. So the semantics of a 
		 * replaced syscall must include "do your own resumption". We therefore
		 * pass the post-handling as a function. */
		replaced_syscalls[gsp->syscall_number](gsp, &post_handling);
	}
	else
	{
		/* HACK: these must not be spilled to the stack at the point where the 
		 * syscall occurs, or they may be lost.  */
		register _Bool stack_zapped = zaps_stack(gsp);
		register uintptr_t *new_top_of_stack = (uintptr_t *) gsp->arg1;
		register uintptr_t *new_rsp = 0;
		
		if (stack_zapped)
		{
			assert(new_top_of_stack);
			
			/* We want to initialize the new stack. Then we will have to fix up 
			 * rsp immediately after return, then jump straight to pretcode,
			 * which does the sigret. Will it work? Yes, it seems to. */
			
			uintptr_t *stack_copy_low;
			__asm__ volatile ("movq %%rsp, %0" : "=rm"(stack_copy_low) : : );
			
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
			new_rsp = new_stack_lowaddr; // (uintptr_t) ((char *) stack_copy_low + fixup_amount);
		}
		
		register unsigned trap_len = instr_len(
			(unsigned char*) gsp->saved_context->uc.uc_mcontext.rip,
			(unsigned char*) -1 /* we don't know where the end of the mapping is */
			);
		
		long int ret = do_real_syscall(gsp);            /* always inlined */
		/* Did our stack actually get zapped? */
		if (stack_zapped)
		{
			uintptr_t *seen_rsp;
			__asm__ volatile ("movq %%rsp, %0" : "=r"(seen_rsp) : : );
			stack_zapped &= (seen_rsp == new_top_of_stack);
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
		 * We could make resume_from_sigframe a macro expanding to an asm volatile.... */
		
		post_handling(gsp, ret); /* okay, because we have a stack (perhaps zeroed/new) */
		/* FIXME: unsafe to access gsp here! Take a copy of *gsp! */
		
		if (!stack_zapped)
		{
			resume_from_sigframe(ret, gsp->saved_context, trap_len);
		}
		else 
		{	
			/* We copied the context into the new stack. So just resume from sigframe
			 * as before, with two minor alterations. Firstly, the caller expects to
			 * resume with the new top-of-stack in rsp. Secondly, we fix up the current rsp
			 * so that the compiler-generated code will find its way to restore_rt 
			 * (i.e. that the function epilogue will use our new stack, not the old one). */
			
			struct ibcs_sigframe *p_frame = (struct ibcs_sigframe *) ((char*) new_top_of_stack - sizeof (struct ibcs_sigframe));
			/* Make sure that the new stack pointer is the one returned to the caller. */
			p_frame->uc.uc_mcontext.rsp = (uintptr_t) new_top_of_stack;
			/* Do the usual manipulations of saved context, to return and resume from the syscall. */
			resume_from_sigframe(ret, p_frame, trap_len);
			/* Hack our rsp so that the epilogue / sigret will execute correctly. */
			__asm__ volatile ("movq %0, %%rsp" : /* no outputs */ : "r"(new_rsp) : "%rsp");
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
	return gsp->syscall_number == __NR_clone
				&& gsp->arg1 /* newstack */ != 0;
}

#endif
