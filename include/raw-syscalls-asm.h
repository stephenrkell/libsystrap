#ifndef RAW_SYSCALLS_ASM_H_
#define RAW_SYSCALLS_ASM_H_

/* This file should contain helper macro definitions
 * useful only for inline asm and/or out-of-line asm
 * for performing syscalls. Keep any C-language stuff in
 * raw-syscalls-impl.h. */

/* HACK: TODO: please drop this and do it less grossly. */
#if defined(__linux__)
#ifdef __x86_64__
#define SYS_sigaction SYS_rt_sigaction
#endif
#endif

/* We want to minimise use of clobbers in our asm snippets.
 * Do syscalls preserve argument registers? Ordinary System V calls don't,
 * but system calls *do*, according to my experiments... I can't find this
 * written down. But the classic /usr/include/asm _syscall*() macros also
 * don't declare them as clobbered.
 *
 * Ideally we'd never clobber argument registers, but instead use constraints.
 * However, GCC extended inline asm does not specify constraints for r10,
 * r8 or r9. It may be possible to use "register asm vars", but I find this
 * feature very untrustworthy (see GCC bug 126237). Ideally we'd try something
 * like a simple nested block:
 *
 * do {
 *   register long int arg4 __asm__("r10") = value_captured_from_context;
 *   DO_SYSCALL4();
 * } while(0)
 *
 * ... and see if this robustly withstands GCC's "intervening clobber" threat,
 * even after code motion. I haven't done this experiment. (Also, remember that
 * I had a real live case of this bug in f980827, which was my attempt to write
 * a syscall handling fast path in C. That was doomed for other reasons, but is
 * a possible test case for this specific issue.)
 *
 * For now we need to make the x86_64 version of DO_SYSCALL{4,5,6} mov
 * args 4--6 into place, from an rm operand, which we must declare as clobbers.
 * That is a potentially extraneous instruction, but is still what the old
 * _syscall{4,5,6}() wrapper in kernel headers used to do.
 *
 * Note that the i386 version does not need this as it uses only registers for
 * which there is an exact constraint.
 *
 * We try to hide this behind POPULATE_ARGREGS and UNPOPULATE_ARGREGS macros.
 */

#define SYSCALL_CLOBBERS(nargs) SYSCALL_CLOBBERS_ ## nargs
#define SYSCALL_CLOBBER_LIST(nargs) \
	ANY_SYSCALL_CLOBBER_LIST  \
	SYSCALL_CLOBBERS(nargs) \
	"cc", "memory"
#define DO_SYSCALL_CLOBBER_LIST(nargs) \
    DO_SYSCALL_EXTRA_CLOBBERS  SYSCALL_CLOBBER_LIST(nargs)
#define POPULATE_ARGREGS(nargs) \
	POPULATE_ARGREGS_ ## nargs
#define UNPOPULATE_ARGREGS(nargs) \
	UNPOPULATE_ARGREGS_ ## nargs

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
#define csyscallnumreg "a"
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
#define cargreg3 "g" /* we rely on POPULATE_ARGREGS for the remainder */
#define cargreg4 "g"
#define cargreg5 "g"
#define POPULATE_ARGREGS_0
#define POPULATE_ARGREGS_1  POPULATE_ARGREGS_0
#define POPULATE_ARGREGS_2  POPULATE_ARGREGS_1
#define POPULATE_ARGREGS_3  POPULATE_ARGREGS_2
#define POPULATE_ARGREGS_4  POPULATE_ARGREGS_3   "\nmov %[arg3], %%r10\n"
#define POPULATE_ARGREGS_5  POPULATE_ARGREGS_4   "\nmov %[arg4], %%r8\n"
#define POPULATE_ARGREGS_6  POPULATE_ARGREGS_5   "\nmov %[arg5], %%r9\n"
#define UNPOPULATE_ARGREGS_0
#define UNPOPULATE_ARGREGS_1  UNPOPULATE_ARGREGS_0
#define UNPOPULATE_ARGREGS_2  UNPOPULATE_ARGREGS_1
#define UNPOPULATE_ARGREGS_3  UNPOPULATE_ARGREGS_2
#define UNPOPULATE_ARGREGS_4  UNPOPULATE_ARGREGS_3
#define UNPOPULATE_ARGREGS_5  UNPOPULATE_ARGREGS_4
#define UNPOPULATE_ARGREGS_6  UNPOPULATE_ARGREGS_5

/* FIXME: why the huge clobber list?
 * According to the ABI,
 * http://refspecs.linuxfoundation.org/elf/x86_64-abi-0.99.pdf
 * only %rcx, %r11 and %rax are clobbered.
 * But the clobber list applies not only to the syscall instruction,
 * but also to our argument-setting sequences.
 * NOTE: we now MUST use constraints for setting argments 0..2. For arguments 3..5,
 * we still set them explicitly because the constraints are not reliable. */
#define ANY_SYSCALL_CLOBBER_LIST "memory", "%rcx", "%r11", 
#define SYSCALL_CLOBBERS_0
#define SYSCALL_CLOBBERS_1 SYSCALL_CLOBBERS_0
#define SYSCALL_CLOBBERS_2 SYSCALL_CLOBBERS_1 
#define SYSCALL_CLOBBERS_3 SYSCALL_CLOBBERS_2 
#define SYSCALL_CLOBBERS_4 SYSCALL_CLOBBERS_3   "%r10",
#define SYSCALL_CLOBBERS_5 SYSCALL_CLOBBERS_4   "%r8",
#define SYSCALL_CLOBBERS_6 SYSCALL_CLOBBERS_5   "%r9",

#define FIX_STACK_ALIGNMENT \
	"movq %%rsp, %%r12\n\
	 andq $0xf, %%r12    # now we have either 8 or 0 in r12 \n\
	 subq %%r12, %%rsp   # fix the stack pointer \n\
	 "
#define UNFIX_STACK_ALIGNMENT \
	"addq %%r12, %%rsp\n"

#define DO_SYSCALL_EXTRA_CLOBBERS  "%r12",

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
#define csyscallnumreg "a"
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
#define cargreg5 "rm" /* use POPULATE_ARGREGS and UNPOPULATE_ARGREGS for this one */
// can't do cargreg5 because there is no constraint for %ebp
#define POPULATE_ARGREGS(nargs) \
	POPULATE_ARGREGS_ ## nargs
#define POPULATE_ARGREGS_0
#define POPULATE_ARGREGS_1  POPULATE_ARGREGS_0
#define POPULATE_ARGREGS_2  POPULATE_ARGREGS_1
#define POPULATE_ARGREGS_3  POPULATE_ARGREGS_2
#define POPULATE_ARGREGS_4  POPULATE_ARGREGS_3
#define POPULATE_ARGREGS_5  POPULATE_ARGREGS_4
#define POPULATE_ARGREGS_6  POPULATE_ARGREGS_5   "\npush %%ebp \n" \
                                                 "\nmov %[arg5], %%ebp \n"
/* We still need to pop %ebp afterwards -- need somewhere to put this */
#define UNPOPULATE_ARGREGS(nargs) \
	UNPOPULATE_ARGREGS_ ## nargs
#define UNPOPULATE_ARGREGS_0
#define UNPOPULATE_ARGREGS_1  UNPOPULATE_ARGREGS_0
#define UNPOPULATE_ARGREGS_2  UNPOPULATE_ARGREGS_1
#define UNPOPULATE_ARGREGS_3  UNPOPULATE_ARGREGS_2
#define UNPOPULATE_ARGREGS_4  UNPOPULATE_ARGREGS_3
#define UNPOPULATE_ARGREGS_5  UNPOPULATE_ARGREGS_4
#define UNPOPULATE_ARGREGS_6  UNPOPULATE_ARGREGS_5   "\npop %%ebp \n"

#define FIX_STACK_ALIGNMENT
#define UNFIX_STACK_ALIGNMENT

#define ANY_SYSCALL_CLOBBER_LIST 
#define SYSCALL_CLOBBERS_0
#define SYSCALL_CLOBBERS_1 SYSCALL_CLOBBERS_0
#define SYSCALL_CLOBBERS_2 SYSCALL_CLOBBERS_1
#define SYSCALL_CLOBBERS_3 SYSCALL_CLOBBERS_2
#define SYSCALL_CLOBBERS_4 SYSCALL_CLOBBERS_3
#define SYSCALL_CLOBBERS_5 SYSCALL_CLOBBERS_4
#define SYSCALL_CLOBBERS_6 SYSCALL_CLOBBERS_5   /* we push/pop %ebp rather than clobber it, since copiler can't cope with this  */

#define DO_SYSCALL_EXTRA_CLOBBERS  /* no extra clobbers on i386...  */

#define SYSCALL_INSTR int $0x80    /* HMM: we could use syscall/sysenter, if we know the microarch
                                    * supports them. But how would we know that? We might know
                                    * at a particular site, if it was originally using that feature.
                                    * But in the case of 'sysenter', the calling $eip is not saved,
          */

#else
#error "Unsupported architecture."
#endif

#define stringify(cond) #cond

// stringify expanded
#define stringifx(cond) stringify(cond)

#endif
