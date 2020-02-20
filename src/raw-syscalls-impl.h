#ifndef RAW_SYSCALLS_H__
#define RAW_SYSCALLS_H__

/* NOTE: this file futzes with the preprocessing environment
 * presented to libc and kernel-user includes. So here be
 * dragons... more importantly, INCLUDE THIS FILE FIRST,
 * otherwise its futzing may be too late to have the intended
 * effect. */

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

#include <sys/types.h>

#if defined(__linux__)
#define SYS_sigaction SYS_rt_sigaction
/* Before including stuff,
 * rename the kernel's distinct struct types,
 * to avoid conflict with glibc. */
#define AVOID_LIBC_SIGNAL_H_

#define timezone __asm_timezone
#define timespec __asm_timespec
#define timeval __asm_timeval
#define itimerval __asm_itimerval
#define itimerspec __asm_itimerspec
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
/* sys/time.h (which later code wants to include)
 * conflicts with linux/time.h, which asm/signal.h includes :-( */
#undef ITIMER_REAL
#undef ITIMER_VIRTUAL
#undef ITIMER_PROF
#undef _STRUCT_TIMESPEC
#include <linux/time.h>
#include <asm/signal.h>
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

/* Our callee-save registers are
 *	 rbp, rbx, r12, r13, r14, r15
 * but all others need to be in the clobber list.
 *	 rdi, rsi, rax, rcx, rdx, r8, r9, r10, r11
 *	 xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15
 *	 condition codes, memory
 */
#define SYSCALL_CLOBBER_LIST \
	"%rdi", "%rsi", "%rax", "%rcx", "%rdx", "%r8", "%r9", "%r10", "%r11", \
	"%xmm0", "%xmm1", "%xmm2", "%xmm3", "%xmm4", "%xmm5", "%xmm6", "%xmm7", "%xmm8", \
	"%xmm9", "%xmm10", "%xmm11", "%xmm12", "%xmm13", "%xmm14", "%xmm15", \
	"cc" /*, "memory" */
#define FIX_STACK_ALIGNMENT \
	"movq %%rsp, %%rax\n\
	 andq $0xf, %%rax    # now we have either 8 or 0 in rax \n\
	 subq %%rax, %%rsp   # fix the stack pointer \n\
	 movq %%rax, %%r12   # save the amount we fixed it up by in r12 \n\
	 "
#define UNFIX_STACK_ALIGNMENT \
	"addq %%r12, %%rsp\n"

#define stringify(cond) #cond

#ifndef assert
#define assert(cond) \
	do { ((cond) ? ((void) 0) : (__assert_fail("Assertion failed: \"" stringify((cond)) "\"", __FILE__, __LINE__, __func__ ))); }  while (0)
#endif

#define write_string(s) raw_write(2, (s), sizeof (s) - 1)
#define write_chars(s, t)  raw_write(2, s, t - s)
#define write_ulong(a)   raw_write(2, fmt_hex_num((a)), 18)

/* In kernel-speak this is a "struct sigframe" / "struct rt_sigframe" --
 * sadly no user-level header defines it. But it seems to be vaguely standard
 * per-architecture (here Intel iBCS). */
struct ibcs_sigframe
{
	char *pretcode;
	struct __asm_ucontext uc;
	struct __asm_siginfo info;
};

void __assert_fail(const char *assertion, const char *file,
                   unsigned int line, const char *function) __attribute__((noreturn));
// FIXME: utility code: prototypes belong here?
unsigned long read_hex_num(const char **p_c, const char *end);

#endif // __RAW_SYSCALLS_H__
