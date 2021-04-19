#define RELF_DEFINE_STRUCTURES
#include "raw-syscalls-impl.h"
#ifdef __linux__
#define sigset_t __asm_sigset_t
#endif
#include <sys/mman.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include "systrap_private.h"
#include "do-syscall.h"

// For debug printing inside handle_sigill we have to know
// that it's our own debug printing in order to filter it
// out of the footprints, hence this noinline function
// rather than using the normal macro
__attribute__ ((noinline)) static void _handle_sigill_debug_printf(int level, const char *fmt, ...) {
	 va_list vl;
	 va_start(vl, fmt);
	 if ((level) <= systrap_debug_level) {
		  vfprintf(stderr, fmt, vl);
		  fflush(stderr);
	 }
	 va_end(vl);
}

/* FIXME: for thread-safety, saved_sysinfo should be a local
 * which we thread through to our callees, all the way to the
 * resume function. How do we get it to the restorer? We can
 * use TLS I guess, though danger.... */
void *saved_sysinfo __attribute__((visibility("hidden")));
void *real_sysinfo __attribute__((visibility("hidden")));
#ifdef __i386__
unsigned sysinfo_int80_offset __attribute__((visibility("hidden")));
#endif
void *fake_sysinfo __attribute__((visibility("hidden")));

/* We may or may not have syscall names linked in.
 * This is just to avoid a dependency on our syscall interface spec.  */
extern const char *syscall_names[SYSCALL_MAX + 1] __attribute__((weak));
void handle_sigill(int n) __attribute__((visibility("hidden")));
void handle_sigill(int n)
{
	unsigned long *frame_base = __builtin_frame_address(0);
	struct ibcs_sigframe *p_frame = (struct ibcs_sigframe *) (frame_base + 1);
#if defined(__i386__)
	unsigned char *tls;
	__asm__("mov %%gs:0x0,%0" : "=r"(tls));
	/* If we haven't set real_sysinfo by now, assume we didn't create a fake one.
	 * We snarf the real one, as it will be unconditionally restored on return. */
	if (!real_sysinfo) real_sysinfo = *(void**)(tls+16);
	void *saved_sysinfo = *(void**)(tls+16);
	*(void**)(tls+16) = real_sysinfo;
#endif

	/* Decode the syscall using sigcontext. */
	_handle_sigill_debug_printf(1, "Took a trap from instruction at %p", p_frame->uc.uc_mcontext.MC_REG_IP);
#ifdef EXECUTABLE
	if (p_frame->uc.uc_mcontext.MC_REG_IP == (uintptr_t) ignore_ud2_addr)
	{
		_handle_sigill_debug_printf(1, " which is our test trap address; continuing.\n");
		resume_from_sigframe(0, p_frame, 2);
#if defined(__i386__)
		*(void**)(tls+16) = saved_sysinfo;
#endif
		return;
	}
#endif

#if defined(__x86_64__)
	unsigned long syscall_num = (unsigned long) p_frame->uc.uc_mcontext.MC_REG(rax, RAX);
#elif defined(__i386__)
	unsigned long syscall_num = (unsigned long) p_frame->uc.uc_mcontext.MC_REG(eax, EAX);
#else
#error "Unrecognised architecture"
#endif
	assert(syscall_num >= 0);
	assert(syscall_num < SYSCALL_MAX);
	_handle_sigill_debug_printf(1, " which we think is syscall %s/%d\n",
		&syscall_names[0] ? syscall_names[syscall_num] : "(names not linked in)", syscall_num);

	/* FIXME: check whether this syscall creates executable mappings; if so,
	 * we make them nx, do the rewrite, then make them x. */

	struct generic_syscall gsp = {
		.saved_context = p_frame,
		.syscall_number = syscall_num,
		.args = {
#if defined(__x86_64__)
			p_frame->uc.uc_mcontext.MC_REG(rdi, RDI),
			p_frame->uc.uc_mcontext.MC_REG(rsi, RSI),
			p_frame->uc.uc_mcontext.MC_REG(rdx, RDX),
			p_frame->uc.uc_mcontext.MC_REG(r10, R10),
			p_frame->uc.uc_mcontext.MC_REG(r8, R8),
			p_frame->uc.uc_mcontext.MC_REG(r9, R9)
#elif defined(__i386__)
			p_frame->uc.uc_mcontext.MC_REG(ebx, EBX),
			p_frame->uc.uc_mcontext.MC_REG(ecx, ECX),
			p_frame->uc.uc_mcontext.MC_REG(edx, EDX),
			p_frame->uc.uc_mcontext.MC_REG(esi, ESI),
			p_frame->uc.uc_mcontext.MC_REG(edi, EDI),
			p_frame->uc.uc_mcontext.MC_REG(ebp, EBP)
#else
#error "Unrecognised architecture."
#endif
		}
	};

	do_syscall_and_resume(&gsp); // inline, but doesn't return?!
	raw_write(2, "blah\n", sizeof "blah\n");
	// FIXME: this isn't hit?!!? Messes with how I thought resumption worked
	_handle_sigill_debug_printf(1, "Resuming from instruction at %p", p_frame->uc.uc_mcontext.MC_REG_IP);
#if defined(__i386__)
	*(void**)(tls+16) = saved_sysinfo;
#endif
}
