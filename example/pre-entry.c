#define _GNU_SOURCE
#include <stdint.h>
#include <unistd.h>
#include <stddef.h>
#include <link.h>
#include <dlfcn.h>
#include <assert.h>
#include "systrap.h"
#include "relf.h"
#include "trace-syscalls.h"

extern uintptr_t __start___replaced_syscalls;
extern uintptr_t __stop___replaced_syscalls;

void __real_enter(void *entry_point);
void __wrap_enter(void *entry_point)
{
	// FIXME: libsystrap isn't being init'd, so force it
	__libsystrap_force_init();
	init_fds();
	/* We want to trap only the inferior ld.so's executable phdr(s).
	 * How do we find them?
	 * We could wrap load_one_phdr -- is that good value?
	 * We will need to do some stuff for vdso,
	 * and some stuff for bootstrapping, but that will probably
	 * be different.
	 * Oh.
	 * But we needed librunt to find the section boundaries.
	 * Does it make sense to run librunt in our primordial ld.so environment?
	 * It wants to be able to do struct R_DEBUG_STRUCT_TAG *find_r_debug(void)
	 * Do we want to create a fake _r_debug so that relf.h can work?
	 * Maybe none of librunt works in this environment?
	 * And what about when our signal handler runs? Does it
	 * need to see the "real" link map of the guest program?
	 * The host/guest distinction seems good.
	 *
	 * Can I locate the _r_debug via the DT_DEBUG, as a fallback?
	 * Then as long as *some* _DYNAMIC with a DT_DEBUG can be found,
	 * we have a pointer to the process's unique "real" _r_debug, which
	 * is defined... where? Yes, in the ld.so.
	 */
	trap_all_mappings();
	install_sigill_handler();
	// FIXME: should go in the real entry point?
#if defined(__i386__)
	if (fake_sysinfo)
	{
		unsigned char *tls;
		__asm__("mov %%gs:0x0,%0" : "=r"(tls));
		*(void**)(tls+16) = fake_sysinfo; // FIXME: need a reference for this please
	}
#endif
	/* Install replacements.
	 * Why not just initialize the replaced_syscalls array itself?
	 * Well, it can't be split across multiple files, unlike this approach.
	 * This is a bit nasty though.
	 */
	unsigned nreplacements = (&__stop___replaced_syscalls - &__start___replaced_syscalls) / 2;
	for (unsigned n = 0; n < nreplacements; ++n)
	{
		uintptr_t syscall_n = (&__start___replaced_syscalls)[2*n];
		assert(syscall_n < SYSCALL_MAX);
		void (*replacement)(struct generic_syscall *s, post_handler *post)
		 = (void*)(&__start___replaced_syscalls)[2*n + 1];
		replaced_syscalls[syscall_n] = replacement;
	}
	find_r_debug()->r_map = NULL;
	__real_enter(entry_point);
}

int __real_load_one_phdr(unsigned long base_addr, int fd, unsigned long vaddr, unsigned long offset,
	unsigned long memsz, unsigned long filesz, _Bool read, _Bool write, _Bool exec);
int __wrap_load_one_phdr(unsigned long base_addr, int fd, unsigned long vaddr, unsigned long offset,
	unsigned long memsz, unsigned long filesz, _Bool read, _Bool write, _Bool exec)
{
	int ret = __real_load_one_phdr(base_addr, fd, vaddr, offset,
		memsz, filesz, read, write, exec);
	if (ret == 0 && exec)
	{
		/* XXX: can't remember what I was thinking when I wrote this code or the comment
		 * below, but I assume it was something about how we instrument the inferior
		 * ld.so. Here we seem to be intercepting the action, in donald, of loading one
		 * phdr. Whereas "running the usual function" means trap_all_mappings, above,
		 * i.e. enumerating all mappings in one big go using librunt, rather than
		 * trapping them as we go along, which we could do from this function.
		 */
		/* HMM. Maybe don't do this, just make librunt work and run the usual function?
		 * Problem is that the parts of librunt that derive from liballocs assume that
		 * a libdl-style runtime is available. Ideally it would not do so, so that even
		 * if librunt is linked into a statically linked executable, it can still do
		 * things. Is this feasible?
		 * 
		 * We could simply link libdl into our program, making it available. Not sure
		 * if librunt will work in such a context, but clearly it should.
		 *
		 * However, once we do this, our fake temporary_link_map seems like the wrong
		 * thing. We make a DT_DEBUG pointing at the inferior's link map. By contrast,
		 * a local libdl would have its own link map.
		 *
		 * Is it possible to implement a chain loader simply by dlopening the dynamic
		 * loader and then loading it? We would have to un-relocate it, assuming we
		 * can't prevent dlopen from relocating it. That sounds nasty.
		 *
		 * A third way might be to splice it into the link map ourselves, without going
		 * through dlopen. But that sounds horrific.
		 *
		 * The least bad option seems to be to use functions from libsystrap that don't
		 * require librunt, and/or to fake up just enough of librunt that we can call
		 * ones that do. We do that faking-up in chain.c
		 */
	}
	return ret;
}
