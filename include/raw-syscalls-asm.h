#ifndef RAW_SYSCALLS_ASM_H_
#define RAW_SYSCALLS_ASM_H_

/* This file should contain helper macro definitions
 * useful only for inline asm and/or out-of-line asm
 * for performing syscalls. Keep any C-language stuff in
 * raw-syscalls-impl.h. */

#if defined(__linux__)
#ifdef __x86_64__
#define SYS_sigaction SYS_rt_sigaction
#endif
#endif

#if defined(__x86_64__)
/* The x86-64 syscall argument passing convention goes like this:
 * RAX: syscall_number
 * RDI: arg0
 * RSI: arg1
 * RDX: arg2
 * R10: arg3
 * R8:  arg4
 * R9:  arg5
 */
#define syscallnumreg rax
#define SYSCALLNUMREG RAX
#define argreg0 rdi
#define argreg1 rsi
#define argreg2 rdx
#define argreg3 r10
#define argreg4 r8
#define argreg5 r9
/* now in GCC extended asm constraint notation */
#define cargreg0 "D"
#define cargreg1 "S"
#define cargreg2 "d"
// #define cargreg3 /* no constraint for r10 */
// #define cargreg4 /* no constraint for r8 */
// #define cargreg5 /* no constraint for r9 */

#define reg_a rax
#define reg_b rbx
#define reg_c rcx
#define reg_d rdx

/* FIXME: why the huge clobber list?
 * According to the ABI,
 * http://refspecs.linuxfoundation.org/elf/x86_64-abi-0.99.pdf
 * only %rcx, %r11 and %rax are clobbered.
 * But the clobber list applies not only to the syscall instruction,
 * but also to our argument-setting sequences.
 * We use the "+a" constraint for rax, so it is not listed. */
#define ANY_SYSCALL_CLOBBER_LIST "%rcx", "%r11"
#define SYSCALL_CLOBBERS_0
#define SYSCALL_CLOBBERS_1 SYSCALL_CLOBBERS_0 ,  "%rdi"
#define SYSCALL_CLOBBERS_2 SYSCALL_CLOBBERS_1 ,  "%rsi"
#define SYSCALL_CLOBBERS_3 SYSCALL_CLOBBERS_2 ,  "%rdx"
#define SYSCALL_CLOBBERS_4 SYSCALL_CLOBBERS_3 ,  "%r10"
#define SYSCALL_CLOBBERS_5 SYSCALL_CLOBBERS_4 ,  "%r8"
#define SYSCALL_CLOBBERS_6 SYSCALL_CLOBBERS_5 ,  "%r9"
#define SYSCALL_CLOBBERS(nargs) SYSCALL_CLOBBERS_ ## nargs
#define SYSCALL_CLOBBER_LIST(nargs) \
	ANY_SYSCALL_CLOBBER_LIST \
	SYSCALL_CLOBBERS(nargs) \
	, "cc" /*, "memory" */

#define FIX_STACK_ALIGNMENT \
	"movq %%rsp, %%r12\n\
	 andq $0xf, %%r12    # now we have either 8 or 0 in r12 \n\
	 subq %%r12, %%rsp   # fix the stack pointer \n\
	 "
#define UNFIX_STACK_ALIGNMENT \
	"addq %%r12, %%rsp\n"

#define DO_SYSCALL_CLOBBER_LIST(nargs) \
   "%r12", SYSCALL_CLOBBER_LIST(nargs)

#define SYSCALL_INSTR syscall

#elif defined(__i386__)

/* On i386 the kernel convention is
 * EAX: syscall_number
 * EBX: arg0
 * ECX: arg1
 * EDX: arg2
 * ESI: arg3
 * EDI: arg4
 * EBP: arg5
 */
#define syscallnumreg eax
#define SYSCALLNUMREG EAX
#define argreg0 ebx
#define argreg1 ecx
#define argreg2 edx
#define argreg3 esi
#define argreg4 edi
#define argreg5 ebp

/* now in GCC extended asm constraint notation */
#define cargreg0 "b"
#define cargreg1 "c"
#define cargreg2 "d"
#define cargreg3 "S"
#define cargreg4 "D"
// can't do cargreg5 because there is no constraint for %ebp

#define reg_a eax
#define reg_b ebx
#define reg_c ecx
#define reg_d edx
/* Our callee-save registers are
 *	 ... all of 'em! we use int $0x80 for now (FIXME: use sysenter instead?)
 * but all others need to be in the clobber list.
 *	 condition codes, memory
 */
#define SYSCALL_CLOBBER_LIST(nargs) \
	"cc" /*, "memory" */
/* HACK: we can't declare all registers as clobbered, as gcc complains --
 * not just about ebp (special) but about unsatisfiable constraints. Instead
 * of clobbering we need to save/restore.
 * GAH. This doesn't work either. E.g. for a 3-argument call...
 * 
 
   0xf7230861 <+1>:     mov    $0x5,%edx
   0xf7230866 <+6>:     mov    %esp,%ebp
   0xf7230868 <+8>:     push   %ebx
   0xf7230869 <+9>:     push   %ecx
   0xf723086a <+10>:    push   %edx
   0xf723086b <+11>:    mov    0x8(%ebp),%ebx
   0xf723086e <+14>:    mov    0xc(%ebp),%ecx
   0xf7230871 <+17>:    mov    0x10(%ebp),%edx
   0xf7230874 <+20>:    mov    %edx,%eax

 ... this code clobbers %edx before it is used to fill %eax, because
 the compiler thinks it *isn't* clobbered.
 COULD try to hack around this by saying "m" instead of "rm", i.e.
 "fill arguments from memory, not registers"
 but will we run into further problems from the compiler thinking
 that $edx (say) is available when it isn't?
 
 The bottom line seems to be that if we want to make a register
 unavailable during the snippet,
 even if we restore its value (so it is not "changed during the snippet" -- or is it?)
 we have to list it as clobbered.
 That means for a 6-argument syscall we run into our old problem again.
 Probably it's harmless there because the compiler won't use %ebp.
 But maybe for a 5-argument syscall even, we will run out of registers.
 
 GCC has a concept of "early clobber" -- useful?
 https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html#Clobbers-and-Scratch-Registers
 
 GCC ought not to have assigned %edx, even though we preserve it,
 because it's not OK to use it in the middle.
 HMM. Doing the push/pop ourselves seems wrong.
 Surely the point is that gcc knows how to do that?
 If it needs to save them (because the asm snippet will clobber them),
 it should do it.
 So, tentatively, remove the push/pop and find another way to
 solve the constraint satisfaction problem, maybe by exploiting the in/outness of %eax
 We may include the push/pop for ebp as a special case.
 
 FIXME: use the constraints! e.g.
 
#define argconstraint0 "d"
 */

/* We need a spare callee-save register for the fixup amount.
 * But we don't have one! We will need everything for the call.
 * Instead we push it four times to preserve 16-byte alignment. */
#define FIX_STACK_ALIGNMENT \
  ""
#if 0
	"mov %%esp, %%eax\n\
	 and $0xf, %%eax    # now we have either 8 or 0 in eax \n\
	 sub %%eax, %%esp   # fix the stack pointer \n\
	 push %%eax \n\
	 push %%eax \n\
	 push %%eax \n\
	 push %%eax \n\
	 "
#endif
/* To undo our push-hack, we pop the replicated value four times.
 * This clobbers ebx. */
#define UNFIX_STACK_ALIGNMENT \

#if 0
	"pop %%ebx\n\
	 pop %%ebx\n\
	 pop %%ebx\n\
	 pop %%ebx\n\
	 add %%ebx, %%esp\n\
	"
#endif
#define DO_SYSCALL_CLOBBER_LIST(nargs) \
   /*"ebx",*/  SYSCALL_CLOBBER_LIST(nargs)

#define SYSCALL_INSTR int $0x80

#else
#error "Unsupported architecture."
#endif

#define stringify(cond) #cond

// stringify expanded
#define stringifx(cond) stringify(cond)

#endif
