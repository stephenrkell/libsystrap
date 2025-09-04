#ifndef RAW_SYSCALLS_IMPL_H_
#define RAW_SYSCALLS_IMPL_H_

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
#include "raw-syscalls-asm.h"

#ifndef assert
#define assert(cond) \
	do { ((cond) ? ((void) 0) : (__assert_fail("Assertion failed: \"" stringify((cond)) "\"", __FILE__, __LINE__, __func__ ))); }  while (0)
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
 */
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

#endif // RAW_SYSCALLS_IMPL_H_
