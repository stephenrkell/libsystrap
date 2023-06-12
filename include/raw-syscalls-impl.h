#ifndef RAW_SYSCALLS_H__
#define RAW_SYSCALLS_H__

/* NOTE: this file futzes with the preprocessing environment
 * presented to libc and kernel-user includes. So here be
 * dragons... more importantly, INCLUDE THIS FILE FIRST,
 * otherwise its futzing may be too late to have the intended
 * effect.
 *
 * The Right Way for us to do this is to generate a standalone
 * (properly namespaced) set of headers, direct from the kernel
 * DWARF, using the tools in my syscall-interfaces repo.
 * FIXME: do this. */

/* for accessing members of mcontext_t */
#ifdef __FreeBSD__
#define MC_REG(lower, upper) mc_ ## lower
#else
/* So that we get the register name #defines from ucontext.h...
 * ... and struct sigaction
 * ... . */
#define _GNU_SOURCE
/* This version works for the libc ucontext / mcontext struct defs,
 * but we don't use those. */
//#define MC_REG(lower, upper) gregs[REG_ ## upper]
/* This version works for the asm/ ones. */
#define MC_REG(lower, upper) lower
#endif

/* Define some generic register aliases */
#if defined(__x86_64__)
#define MC_REG_IP MC_REG(rip, RIP)
#define MC_REG_SP MC_REG(rsp, RSP)
#elif defined(__i386__)
#define MC_REG_IP MC_REG(eip, EIP)
#define MC_REG_SP MC_REG(esp, ESP)
#else
#error "Unrecognised architecture"
#endif

#if defined(__linux__)
#ifdef __x86_64__
#define SYS_sigaction SYS_rt_sigaction
#endif
/* Before including stuff,
 * rename the kernel's distinct struct types,
 * to avoid conflict with glibc. */
#define AVOID_LIBC_SIGNAL_H_

/* sys/time.h (which later code wants to include)
 * conflicts with linux/time.h, which asm/signal.h includes :-(
 * linux/time.h #defines ITIMER_* to their literal values,
 * but sys/time.h wants to define an enum using the tokens
 * as the enumerators. So if we're not careful we'll get "0 = 0"
 * coming out in the enum. We need to include sys/time.h first.
 * sys/time.h also defines (by inclusion) struct timeval, which
 * Linux wants to define. */
// #define timezone __asm_timezone
// #define timespec __asm_timespec
// #define timeval __asm_timeval
// #define itimerval __asm_itimerval
// #define itimerspec __asm_itimerspec
#define timezone __libc_timezone
struct __libc_timezone;
#define timespec __libc_timespec
struct __libc_timespec;
#define timeval __libc_timeval
struct __libc_timeval;
#define itimerval __libc_itimerval
#define itimerspec __libc_itimerspec
/* sys/types.h, but working around musl's paren-light style */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wparentheses"
#include <sys/types.h>
#pragma GCC diagnostic pop
#include <sys/time.h>
#undef timezone
#undef timespec
#undef timeval
#undef itimerval
#undef itimerspec
#undef _STRUCT_TIMESPEC
#undef _STRUCT_TIMEVAL
/* Now we've got all the usual sys time stuff, __libc_-prefixed.
 * And linux/time.h wants to define its own version. */
#include <linux/time.h>
#define __asm_timezone timezone
#define __asm_timespec timespec
#define __asm_timeval timeval
#define __asm_itimerval itimerval
#define __asm_itimerspec itimerspec
#undef ITIMER_REAL
#undef ITIMER_VIRTUAL
#undef ITIMER_PROF
#define sigset_t __asm_sigset_t
#define sigaction __asm_sigaction
#define siginfo __asm_siginfo
#define siginfo_t __asm_siginfo_t
#define sigval __asm_sigval
#define sigval_t __asm_sigval_t
#define siginfo __asm_siginfo
#define stack_t __asm_stack_t
#define ucontext __asm_ucontext
#define pid_t __kernel_pid_t
#include <asm/signal.h> /* is going to include linux/time.h, so we did it above */
#include <asm/sigcontext.h>
#include <asm/siginfo.h>
#include <asm/ucontext.h>
#include <asm/types.h>
#include <asm/posix_types.h>
#include <asm-generic/stat.h>
#include <asm/fcntl.h>
#include <asm/ucontext.h>
#undef timezone
#undef timespec
#undef timeval
#undef itimerval
#undef itimerspec

#undef sigset_t
#undef sigaction
#undef siginfo
#undef siginfo_t
#undef sigval
#undef sigval_t
#undef siginfo
#undef stack_t
#undef pid_t

#elif defined(__FreeBSD__)
#include <sys/signal.h>
#include <sys/stat.h>
#include <fcntl.h>
/* FreeBSD doesn't have separate definitions of these,
 * so just alias the __asm_* ones to the vanilla ones.
 * Unlike above, where we want to avoid collisions,
 * we only need to do this for the ones we use. */
#define __asm_timezone timezone
#define __asm_timespec timespec
#define __asm_timeval timeval
#define __asm_itimerval itimerval
#define __asm_itimerspec itimerspec
#define __asm_sigset_t sigset_t
#define __asm_sigaction sigaction
#define __asm_siginfo siginfo
#define __asm_ucontext ucontext
#define __kernel_pid_t pid_t
#include <sys/ucontext.h>
#else
#error "Unrecognised platform."
#endif

#include <stdint.h>

#include "raw-syscalls-defs.h"

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

#ifndef assert
#define assert(cond) \
	do { ((cond) ? ((void) 0) : (__assert_fail("Assertion failed: \"" stringify((cond)) "\"", __FILE__, __LINE__, __func__ ))); }  while (0)
#endif

/* We must have librunt for these, after fmt_hex_num was moved there. */
#ifndef write_string
#define write_string(s) raw_write(2, (s), sizeof (s) - 1)
#endif
#ifndef write_chars
#define write_chars(s, t)  raw_write(2, s, t - s)
#endif
const char *fmt_hex_num(unsigned long n) __attribute__((visibility("hidden")));
#ifndef write_ulong
#define write_ulong(a)   raw_write(2, fmt_hex_num((a)), 18)
#endif

#define DO_EXIT_SYSCALL(exitcode) \
	long retcode = (exitcode); \
	long op = SYS_exit; \
	__asm__ volatile ("mov %0, %%"stringifx(argreg0)"      # \n\
			  "FIX_STACK_ALIGNMENT " \n\
			   mov %1, %%"stringifx(syscallnumreg)"      # \n\
			   "stringifx(SYSCALL_INSTR)"	     # do the syscall \n\
			  "UNFIX_STACK_ALIGNMENT " \n" \
	  : /* no output*/ : "rm"(retcode), "rm"(op) : DO_SYSCALL_CLOBBER_LIST(1));

#define DO_SIGRETURN_SYSCALL(num /* SYS_rt_sigreturn */) \
	long unused_val = 0; \
	long op = num; \
	__asm__ volatile ("mov %0, %%"stringifx(argreg0)"      # \n\
			  "FIX_STACK_ALIGNMENT " \n\
			   mov %1, %%"stringifx(syscallnumreg)"      # \n\
			   "stringifx(SYSCALL_INSTR)"	     # do the syscall \n\
			  "UNFIX_STACK_ALIGNMENT " \n" \
	  : /* no output*/ : "rm"(unused_val), "rm"(op) : DO_SYSCALL_CLOBBER_LIST(1));

/* In kernel-speak this is a "struct sigframe" / "struct rt_sigframe" --
 * sadly no user-level header defines it. But it seems to be vaguely standard
 * per-architecture (here Intel iBCS). */
struct ibcs_sigframe
{
	char *pretcode;
#ifdef __i386__
	int sig; // on x86 sigill is not RT, so we get a non-rt sigframe
#endif
#ifdef __i386__
	struct {
		struct sigcontext uc_mcontext;
	} uc;
#else
	struct __asm_ucontext uc;
#endif
	struct __asm_siginfo info; // FIXME: this is wrong on i386
};

/* Because a raw syscall might zap the stack, syscall-performing code should
 * avoid creating a local variable to hold the precalculated trap length. Use
 * these macros to calculate trap length at the point of use. Problem:
 * struct ibcs_sigframe is opaque to external callers, but syscall-replacing
 * clients really need access to it. Well, specifically they need access to
 * a struct mcontext, since the rest is arch-specific and we should be able
 * to hide it from them for the most part. Let' see if we can make that work. */
#define trap_site(mctxt) ((mctxt)->MC_REG_IP)
#ifndef __i386__
#define trap_len(mctxt) 2 /* FIXME: x86_64-specific */
#else /* i386 / sysinfo -specific stuff */
#define trap_site_sysinfo_offset(mctxt) ((intptr_t)(trap_site(mctxt)) - (intptr_t)(fake_sysinfo))
#define trap_site_is_in_fake_vdso(mctxt) (trap_site_sysinfo_offset(mctxt) >= 0 && \
   trap_site_sysinfo_offset(mctxt) < KERNEL_VSYSCALL_MAX_SIZE)
#define trap_len(mctxt) ( \
    (trap_site_is_in_fake_vdso(mctxt)) ? (2 + sysinfo_int80_offset - trap_site_sysinfo_offset(mctxt)) : 2 \
)
#endif

extern inline void
__attribute__((always_inline,gnu_inline))
fixup_sigframe_for_return(struct ibcs_sigframe *p_frame, long int ret, unsigned instr_len, void *maybe_new_sp)
{
	/* Copy the return value of the emulated syscall into the trapping context, and
	 * resume from *after* the faulting instruction.
	 *
	 * Writing through p_frame is undefined behaviour in C, or at least, gcc optimises
	 * it away for me. So do it in volatile assembly. */

	// set the return value
	// HACK: it's in the same place as the syscall number
	__asm__ volatile ("mov %1, %0"
		 : "=m"(p_frame->uc.uc_mcontext.MC_REG(syscallnumreg, SYSCALLNUMREG))
		 : "r"(ret) : "memory");
	// adjust the saved program counter to point past the trapping instr
	__asm__ volatile ("mov %1, %0"
		: "=m"(p_frame->uc.uc_mcontext.MC_REG_IP)
		: "r"(p_frame->uc.uc_mcontext.MC_REG_IP + instr_len) : "memory");
	if (maybe_new_sp)
	{
		__asm__ volatile ("mov %1, %0"
			: "=m"(p_frame->uc.uc_mcontext.MC_REG_SP)
			: "r"(maybe_new_sp) : "memory");
	}
}

// FIXME: utility code: prototypes belong here?
unsigned long read_hex_num(const char **p_c, const char *end);

#endif // __RAW_SYSCALLS_H__
