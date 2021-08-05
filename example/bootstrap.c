#define _GNU_SOURCE

// we need ibcs_sigframe, so we need the asm ucontext stuff
#include "raw-syscalls-impl.h" /* always include raw-syscalls first, and let it do the asm includes */

#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h> // for memcpy
#include "dso-meta.h" // includes link.h
#include "systrap.h"
#include "vas.h"
#include "trace-syscalls.h" // FIXME: move us out of example/ into src/

/* Replacement syscalls for
 *
 * - in-process bootstrapping of instrumentation
 *         (mmap, mmap2?, mremap, munmap)
 * - cross-process bootstrapping via execve() rewriting
 *         (also execveat)
 * */

#if defined(__i386__)
#define ASMPTR ".long"
#elif defined(__x86_64__)
#define ASMPTR ".quad"
#else
#error "Unsupported architecture"
#endif
 
#define real_comma ,
#define comma real_comma
#define init_from_generic(t, n, num) t n = (t) s->args[num]
#define expand_name(t, n, num) n
#define expand_name_and_type(t, n, num) t n

// #define expandz(cond) cond
#define expandy(cond) cond
#define expand(cond) expandy(cond)
#define stringify(cond) #cond
// stringify expanded
#define stringifx(cond) stringify(cond)

#define REPLACE(name) \
/* we expect a name_args and name_ret_t... */ \
/* ... name_args is a higher-order macro expandable with expand_name, above, and friends... */ \
static void replacement_ ## name (struct generic_syscall *s, post_handler *post) __attribute__((unused)); \
static void replacement_ ## name (struct generic_syscall *s, post_handler *post) \
{ \
	name ## _args(init_from_generic, ;); \
	name ## _ret_t ret = bootstrap_ ## name( name ## _args(expand_name, comma) ); \
	post(s, (uintptr_t) ret, 0); \
	fixup_sigframe_for_return(s->saved_context, (long int) ret, \
	    trap_len(&s->saved_context->uc.uc_mcontext), NULL); \
} \
__asm__( ".pushsection __replaced_syscalls,\"aw\", @progbits\n"\
  ASMPTR " " stringifx(expand(__NR_ ## name)) "\n"\
  ASMPTR " replacement_" #name "\n"\
  ".popsection\n"\
);
#define bootstrap_proto(n) n ## _ret_t bootstrap_ ## n( n ## _args (expand_name_and_type, comma) )
// count argv entries, not including terminator
#ifdef CHAIN_LOADER
#include "chain.h"
static unsigned argv_count(char *const *argv)
{
	unsigned n = 0;
	while (*argv++) ++n;
	return n;
}

#define execve_ret_t int
#define execve_args(v, sep) \
    v(const char *, filename, 0) sep   v(char *const *, argv, 1) sep \
    v(char *const *, envp, 2)
bootstrap_proto(execve)
{
	unsigned count = argv_count(argv);
	char **new_argv = alloca((argv_count(argv) + 2) * sizeof (char*));
	new_argv[0] = OUR_LDSO_NAME;
	memcpy(new_argv + 1, argv, (count + 1) * sizeof (char*));
	return execve(OUR_LDSO_NAME, new_argv, envp);
}
REPLACE(execve)

#define execveat_ret_t int
#define execveat_args(v, sep) \
    v(int, dirfd, 0) sep  v(const char *, filename, 1) sep \
    v(char *const *, argv, 2) sep  v(char *const *, envp, 3)
bootstrap_proto(execveat)
{
	unsigned count = argv_count(argv);
	char **new_argv = alloca((argv_count(argv) + 2) * sizeof (char*));
	new_argv[0] = OUR_LDSO_NAME;
	memcpy(new_argv + 1, argv, (count + 1) * sizeof (char*));
	/* FIXME: Linux has an execveat syscall but there's no wrapper.
	 * I'm not even sure the prototype is right. */
	return syscall(/*__NR_execveat*/ 358, dirfd, OUR_LDSO_NAME, new_argv, envp);
}
REPLACE(execveat)
#endif /* CHAIN_LOADER */

#ifdef __i386__
#define mmap2_ret_t void *
#define mmap2_args(v, sep) \
    v(void *, addr, 0) sep   v(size_t, length, 1) sep \
    v(int, prot, 2) sep      v(int, flags, 3) sep \
    v(int, fd, 4) sep        v(unsigned long, pgoffset, 5)
bootstrap_proto(mmap2)
{
	if (!(prot & PROT_EXEC))
	{
		return (void*) syscall(__NR_mmap2, addr, length, prot, flags, fd, pgoffset);
	}
	// else...
	// always map writable, non-executable
	int temporary_prot = (prot | PROT_WRITE | PROT_READ) & ~PROT_EXEC;
	void *mapping = (void*) syscall(__NR_mmap2, addr, length, temporary_prot, flags, fd, pgoffset);
	unsigned long long offset = (unsigned long long) pgoffset * page_size;
#else
#define mmap_ret_t void *
#define mmap_args(v, sep) \
    v(void *, addr, 0) sep   v(size_t, length, 1) sep \
    v(int, prot, 2) sep      v(int, flags, 3) sep \
    v(int, fd, 4) sep        v(unsigned long, offset, 5)
bootstrap_proto(mmap)
{
	if (!(prot & PROT_EXEC)) return mmap(addr, length, prot, flags, fd, offset);
	// else...
	// always map writable, non-executable
	int temporary_prot = (prot | PROT_WRITE | PROT_READ) & ~PROT_EXEC;
	void *mapping = (void*) mmap(addr, length, temporary_prot, flags, fd, offset);
#endif
	/* Trap -- HOW? We could go eager or lazy; let's try eager for now.
	 *
	 * When we are called, we may not be able to runt-reflect on the
	 * mapping, because it is probably not in the link map.
	 *
	 * How does liballocs deal with this? It doesn't. It doesn't track
	 * what's going on during ld.so. When it catches dlopen mmaps, it
	 * registers the segments (etc) later.
	 *
	 * Our best bet is to tweak how we do trap_one_executable_region()
	 * so that we can provide the section headers. Given the fd, it will
	 * be trivial to scrape them out of the ELF file. This refactoring
	 * is now done.
	 */
	/* Doesn't this undermine the concept of librunt as sitting underneath
	 * us and similar tools? Maybe a little. But we are still using relf.h
	 * a lot, and much of the librunt utility code is useful in code contexts
	 * that aren't pre-dynload/link, e.g. pretty-printing addresses etc.
	 *
	 * Also, it's inefficient. We're doing all this snarfing for every mmap,
	 * and basically we're re-gathering the same metadata that librunt can
	 * grab for us "the right way" shortly, once the ld.so has registered the
	 * mapping. However, it's simple.
	 *
	 * We may decide to be lazy: clear execute permission, record the range
	 * as virtually executable, and wait for the SEGV, which we must handle.
	 * This would also let us trap gradually, which may be good for performance
	 * (not sure... it means taking more faults). Handling SEGV is necessary if
	 * we're going to do the 'virtual R|X mappings' trick. */
	if (mapping != MAP_FAILED)
	{
		ElfW(Ehdr) ehdr;
		ssize_t nread;
		uintptr_t inferred_vaddr;
		/* OK, we've mapped something. */
		if (fd == -1) goto no_file;
		// by the way, what's the filename?
		char buf[sizeof "/proc/0000000000/fd/0000000000"];
		int ret = snprintf(buf, sizeof buf, "/proc/%d/fd/%d", getpid(), fd);
		char buf2[/*PATH_MAX*/ 4096];
		if (ret > 0)
		{
			ret = readlink(buf, buf2, sizeof buf2);
			if (ret > 0 && ret < sizeof buf2)
			{ buf2[ret] = '\0'; ret = 0; /* success */ }
		} else ret = 1; // failed
		const char *filename = (ret == 0) ? buf2 : "(unknown file)";
		nread = pread(fd, &ehdr, sizeof ehdr, 0);
		if (nread != sizeof ehdr) goto fail;
		if (0 == memcmp(&ehdr, "\177ELF", 4))
		{
			ElfW(Shdr) shdrs[ehdr.e_shnum];
			ElfW(Phdr) *matched = NULL;
			_Bool match_is_unique = 1;
			for (unsigned i = 0; i < ehdr.e_shnum; ++i)
			{
				nread = pread(fd, &shdrs[i], sizeof shdrs[i],
					ehdr.e_shoff + i*ehdr.e_shentsize);
				if (nread != sizeof shdrs[i]) goto fail;
			}
			ElfW(Phdr) phdrs[ehdr.e_phnum];
			for (unsigned i = 0; i < ehdr.e_phnum; ++i)
			{
				nread = pread(fd, &phdrs[i], sizeof phdrs[i],
					ehdr.e_phoff + i*ehdr.e_phentsize);
				if (nread != sizeof phdrs[i]) goto fail;
			}
			for (ElfW(Phdr) *p = &phdrs[0]; p < &phdrs[ehdr.e_phnum]; ++p)
			{
				if (p->p_type != PT_LOAD) continue;
				_Bool offset_matches = ((ROUND_DOWN(p->p_offset, page_size)) == offset);
				if (offset_matches)
				{
					// what if there are two mappings with the same offset/pgoffset?
					if (matched) match_is_unique = 0;
					matched = p;
				}
			}
			if (matched && !match_is_unique)
			{
				debug_printf(0, "strange ELF file being mapped");
			}
			if (matched)
			{
				inferred_vaddr = (uintptr_t) mapping - matched->p_vaddr;
				// now we can trap the bugger
				trap_one_executable_region_given_shdrs(mapping, (void*) mapping + length,
					filename, /* is_writable */ 1, /* is_readable */ 1,
					shdrs, ehdr.e_shnum,
					/* HMM. What's the load address of the file?
					 * We can infer this if we can match the mapping to a phdr
					 * of the file, but not otherwise.
					 * In general, multiple phdrs may map the same parts of the
					 * file. Can we really not get more insight into the ld.so's
					 * state? I think SEGV is the only way. */
					inferred_vaddr);

				// OK, done the trap so let's fix up the protection (always different)
				ret = mprotect(mapping, length, prot);
				if (ret != 0) goto fail;
			}
			else // !matched
			{
				// can't infer vaddr, so can't trap it. Proceed without executability
				debug_printf(0, "Can't infer vaddr for mapping of %s offset 0x%llx", filename, (unsigned long long) offset);
				goto ret;
			}
		} else goto not_elf;

		goto ret; // success
	no_file:
		/* It's an anonymous mapping. Probably it's supposed
		 * to be writable. We'll support this eventually. */
		debug_printf(0, "Anonymous executable mapping at %p", mapping);
		goto ret;
	not_elf:
		/* Well this is interesting. We've mapped part of a file and the
		 * caller wanted it executable, but it's not an ELF file. */
		debug_printf(0, "Failing non-ELF  executable file mapping at %p", mapping);
		goto fail;
	fail:
		// fail the whole thing
		munmap(mapping, length);
		return MAP_FAILED;
	}
ret:
	return mapping;

} // end of mmap2 (32-bit) or mmap (otherwise)
#if defined(__i386__)
REPLACE(mmap2)

#define mmap_ret_t void *
#define mmap_args(v, sep) \
    v(void *, addr, 0) sep   v(size_t, length, 1) sep \
    v(int, prot, 2) sep      v(int, flags, 3) sep \
    v(int, fd, 4) sep        v(unsigned long, offset, 5)
bootstrap_proto(mmap)
{
	if (!(prot & PROT_EXEC)) return mmap(addr, length, prot, flags, fd, offset);
	unsigned delta = offset - ROUND_DOWN(offset, page_size);
	length += delta;
	addr -= delta;
	return bootstrap_mmap2(addr, length, prot, flags, fd, offset / page_size);
}
REPLACE(mmap)
#else
REPLACE(mmap)
#endif

#define mprotect_ret_t int
#define mprotect_args(v, sep) \
    v(void *, addr, 0) sep    v(size_t, len, 1) sep    v(int, prot, 2)
bootstrap_proto(mprotect)
{
	if (!((prot & PROT_WRITE) && (prot & PROT_EXEC)))
	{
		return mprotect(addr, len, prot);
	}
	/* We ideally want to assume that runt-reflection works here. But that might
	 * not be the case if the ld.so does a PROT_NONE mapping and then mprotects
	 * each segment appropriately. Unlike mmap(), we don't have the fd, so we
	 * are in even less of a position to guess our way to the section headers. */
	// FIXME
	return mprotect(addr, len, prot);
}
REPLACE(mprotect)

#define mremap_ret_t void *
#define mremap_args(v, sep) \
    v(void *, old_address, 0) sep   v(size_t, old_size, 1) sep \
    v(size_t, new_size, 2) sep      v(int, flags, 3) sep \
    v(void *, new_address, 4)
bootstrap_proto(mremap)
{
	if (!((flags & PROT_WRITE) && (flags & PROT_EXEC)))
	{
		return mremap(old_address, old_size, new_size, flags, new_address);
	}
	// else... FIXME
	return mremap(old_address, old_size, new_size, flags & ~PROT_EXEC, new_address);
}
REPLACE(mremap)

#define munmap_ret_t int
#define munmap_args(v, sep) \
    v(void *, addr, 0) sep   v(size_t, length, 1)
bootstrap_proto(munmap)
{
	return munmap(addr, length);
}
REPLACE(munmap)
