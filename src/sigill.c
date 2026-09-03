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
unsigned sysinfo_sysenter_offset __attribute__((visibility("hidden")));
#endif
void *fake_sysinfo __attribute__((visibility("hidden")));

/* We may or may not have syscall names linked in.
 * This is just to avoid a dependency on our syscall interface spec.  */
extern const char *syscall_names[SYSCALL_MAX + 1] __attribute__((weak));
void handle_sigill(int n) __attribute__((visibility("hidden")));
void handle_sigill(int n)
{
	/* FIXME: CHECK whether this is one of our trap sites!
	 * If it isn't, and if the user has their own sigill handler
	 * (which we stashed somewhere rather than actually allowing
	 * to be installed) we need to tail-call that. For now, we
	 * just do a quick check whether we came from a ud2, and if
	 * not, abort. */
	unsigned long *frame_base = __builtin_frame_address(0);
	struct ibcs_sigframe *p_frame = (struct ibcs_sigframe *) (frame_base + 1);
	if (!is_ud2((void*) p_frame->uc.uc_mcontext.MC_REG_IP)) raw_exit(128 + SIGABRT);
#if defined(__i386__)
	unsigned char *tls;
	__asm__("mov %%gs:0x0,%0" : "=r"(tls));
	/* If we haven't set real_sysinfo by now, assume we didn't create a fake one.
	 * We snarf the real one, as it will be unconditionally restored on return. */
	if (!real_sysinfo) real_sysinfo = *(void**)(tls+16);
	/* Save the possibly-fake sysinfo that was active in the user code,
	 * and switch to the real one, for our use.
	 *
	 * FIXME: if a nested signal handler runs here, we will expose the
	 * real sysinfo. We could do various things about this, e.g. refrain
	 * from using vdso calls ourselves (cf. now we let musl decide for us...). */
	void *saved_sysinfo = *(void**)(tls+16);
	*(void**)(tls+16) = real_sysinfo;
#endif
	/* NEW: let's exit the sighandler as quickly as possible and instead
	 * handle everything from an asm path in non-signal context. */
#if 0 && defined(__x86_64__)  /* <-- remove when ready */
	__asm__ volatile ("mov %1, %0" : "=m"(p_frame->uc.uc_mcontext.MC_REG(rcx, RCX)) : "r"(p_frame->uc.uc_mcontext.MC_REG_IP));
	__asm__ volatile ("mov %1, %0" : "=m"(p_frame->uc.uc_mcontext.MC_REG_IP) : "r"(&__systrap_call_handler));
#if 0
	p_frame->uc.uc_mcontext.MC_REG(rcx, RCX) = p_frame->uc.uc_mcontext.MC_REG_IP;
	p_frame->uc.uc_mcontext.MC_REG_IP = &__systrap_call_handler;
#endif
	return;
#elif defined(__i386__)
	/* Are we free to clobber %ecx in 32-bit mode? No, I don't think so.
	 * Maybe we could push something? This means we can't ensure that
	 * the handler will get the same register file that was current at
	 * the system call site. The other option is to use a thread-local,
	 * which is playing with fire... do we have working TLS in this
	 * context, even? Let's just not support call-frame hnadling on
	 * i386 for now. We could do something like (1) on the initial thread,
	 * save space high up the stack, while (2) on an non-initial thread,
	 * ensure we have working TLS by then. */
#elif defined(__x86_64__)
	/* continue with the fallback path below */
#else
#error "Unrecognised architecture"
#endif

	/* Decode the syscall using sigcontext. */
	_handle_sigill_debug_printf(1, "Took a trap from instruction at %p",
			(void*) p_frame->uc.uc_mcontext.MC_REG_IP);

#if defined(__x86_64__)
	unsigned long syscall_num = (unsigned long) p_frame->uc.uc_mcontext.MC_REG(rax, RAX);
#elif defined(__i386__)
	unsigned long syscall_num = (unsigned long) p_frame->uc.uc_mcontext.MC_REG(eax, EAX);
#else
#error "Unrecognised architecture"
#endif
	assert(syscall_num >= 0);
	assert(syscall_num < SYSCALL_MAX);
	_handle_sigill_debug_printf(1, " which we think is syscall %s/%ld\n",
		&syscall_names[0] ? syscall_names[syscall_num] : "(names not linked in)", syscall_num);

	/* FIXME: check whether this syscall creates executable mappings; if so,
	 * we make them nx, do the rewrite, then make them x. */

	struct generic_syscall gsp = {
		.saved_context = p_frame,
		.site = (void*) p_frame->uc.uc_mcontext.MC_REG_IP,
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
			/* The sixth arg is special:
			 * If we are doing sysenter, it is *pointed to* by %ebp.
			 * If we are doing int 80, it *is* ebp.
			 * Our do_syscall code just wants to put a value into %ebp.
			 * It will use int 80.
			 * So if we have come from the unique sysenter instruction,
			 * we want to snarf 0(%ebp), otherwise %ebp.
			 *
			 * Further problem:
			 * what if we don't have a six-arg call? Then there
			 * may be nothing good in the slot. To check %ebp is
			 * not totally bogus, we want to test it against the
			 * bounds of the current stack. Two problems:
			 *
			 * 1. if sigaltstack is in effect, this will be broken.
			 *
			 * 2. How do we get the bounds of the current stack anyway?
			 *
			 * For now, a giant HACK: within two pages of saved esp. */
#define MAYBE_DEREF_EBP(ebp, esp) \
			(((ebp) >= (esp) && ((ebp)-(esp) < 8192)) ? *(uintptr_t*)(ebp) : 0)
#define IS_SYSENTER(eip) \
			((eip) == (uintptr_t) fake_sysinfo + sysinfo_sysenter_offset)
			IS_SYSENTER(p_frame->uc.uc_mcontext.MC_REG_IP)
			 ? MAYBE_DEREF_EBP(p_frame->uc.uc_mcontext.MC_REG(ebp, EBP),
			                   p_frame->uc.uc_mcontext.MC_REG(esp, ESP))
			 : p_frame->uc.uc_mcontext.MC_REG(ebp, EBP)
#else
#error "Unrecognised architecture."
#endif
		}
	};

	/* If the syscall does not have a replacement installed, we follow a generic
	 * emulation path.
	 *
	 * The 'post_handling' argument is worth explaining.
	 * A typical replaced_syscall function looks like this.

    void frob_replacement(struct generic_syscall *s, post_handler *post)
    {
            // Unpack the arguments.
            void *old_addr = (void*) s->args[0];
            ...
            // Do the call we actually want to do
            void *ret = raw_frob(old_addr ^ 0x42);
            // Do the post-handling
            post(s, (long) ret);
            fixup_sigframe_for_return(s->saved_context, (long) ret, 2);
        // NOW return to the caller so it can do the resume for us
    }

	 * Our SIGILL handler will always pass the "post_handler" because each
	 * client may have some common post-syscall stuff to do, for syscalls that
	 * are replaced and for syscalls that are trapped and emulated. In other
	 * words we support both "around" (pre/post) advice of syscalls and
	 * "replace". And the replacement has the option of calling the post-handling.
	 * (The pre-handling is always called, before the replacement.)
	 *
	 * We took away the option for some replacement syscalls to do their own
	 * fixup and tell the handler they don't need the usual fixup... will see
	 * if this bites. Support for a replacement clone() seems to be the issue...
	 * more below.
	 */
	if (__systrap_pre_handling) __systrap_pre_handling(&gsp);
	long ret;
	if (replaced_syscalls[gsp.syscall_number])
	{
		/* Since replaced_syscalls holds function pointers, these calls will 
		 * not be inlined. It follows that if the call ends up doing a real
		 * clone(), we have no way to get back here. So the semantics of a
		 * replaced syscall must include "do your own resumption".

		 * Returning to the above after a while: WHAT does this mean? I can think of two things.
		 * - In the cloned child, the post-handler should run twice.
		 * - clone() requires bespoke sigframe fixup.
		 *
		 * Does sigreturn also run twice? Currently, yes: we fake up a sigframe so that we can
		 * sigreturn even from a thread/stack that was not signalled. So the return path should
		 * be the same, and we should be able to call the post handling -- as long as we don't
		 * ask it to fix up the sigframe.
		 *
		 * Replacement syscalls should have the *option* of doing their own sigframe fixup,
		 * just like we have for our own clone handler. That's why we don't just do the
		 * fixup below, along the exit path; the replacement has to do it, as shown in
		 * frob_replacement() above.
		 *
		 * Does clone() prevent control from returning here? Actually no... our
		 * clone() handling is painstakingly crafted to return through here
		 * and hit the usual sigreturn path, even in the child thread.
		 */
		ret = replaced_syscalls[gsp.syscall_number](&gsp);  /* XXX: this skips the post-syscall handling! FIXME! */
	}
	else
	{
		ret = do_generic_syscall_and_fixup(&gsp); /* this does the post-syscall handling */
	}
	if (__systrap_post_handling) __systrap_post_handling(&gsp, ret);
out:
	_handle_sigill_debug_printf(1, "Resuming from instruction at %p\n", p_frame->uc.uc_mcontext.MC_REG_IP);
#if defined(__i386__)
	*(void**)(tls+16) = saved_sysinfo;
	return;
#else
	return;
#endif
}
