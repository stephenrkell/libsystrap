#define RELF_DEFINE_STRUCTURES
#include "raw-syscalls-impl.h"
#ifdef __linux__
#define sigset_t __asm_sigset_t
#endif
#include <sys/mman.h>
#include <stdint.h>
#include <stdarg.h>
#include "systrap_private.h"
#include "do-syscall.h"

// For debug printing inside handle_sigill we have to know
// that it's our own debug printing in order to filter it
// out of the footprints, hence this noinline function
// rather than using the normal macro
__attribute__ ((noinline)) static void _handle_sigill_debug_printf(int level, const char *fmt, ...) {
	 va_list vl;
	 va_start(vl, fmt);
	 if ((level) <= debug_level) {
		  vfprintf(*p_err_stream, fmt, vl);
		  fflush(*p_err_stream);
	 }
	 va_end(vl);
}

/* We may or may not have syscall names linked in.
 * This is just to avoid a dependency on our syscall interface spec.  */
extern const char *syscall_names[SYSCALL_MAX + 1] __attribute__((weak));
void handle_sigill(int n) __attribute__((visibility("hidden")));
void handle_sigill(int n)
{
	unsigned long *frame_base = __builtin_frame_address(0);
	struct ibcs_sigframe *p_frame = (struct ibcs_sigframe *) (frame_base + 1);

	/* Decode the syscall using sigcontext. */
	_handle_sigill_debug_printf(1, "Took a trap from instruction at %p", p_frame->uc.uc_mcontext.MC_REG(rip, RIP));
#ifdef EXECUTABLE
	if (p_frame->uc.uc_mcontext.MC_REG_IP == (uintptr_t) ignore_ud2_addr)
	{
		_handle_sigill_debug_printf(1, " which is our test trap address; continuing.\n");
		resume_from_sigframe(0, p_frame, 2);
		return;
	}
#endif

#if defined(__x86_64__)
	unsigned long syscall_num = (unsigned long) p_frame->uc.uc_mcontext.MC_REG(rax, RAX);
#elif defined(__i386__
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
#elif define(__i386__)
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

	do_syscall_and_resume(&gsp); // inline
}
