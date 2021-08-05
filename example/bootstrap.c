#define _GNU_SOURCE

// we need ibcs_sigframe, so we need the asm ucontext stuff
#include "raw-syscalls-impl.h" /* always include raw-syscalls first, and let it do the asm includes */

#include <stdio.h>
#include <assert.h>

/* sys/types.h, but working around musl's paren-light style */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wparentheses"
#include <sys/types.h>
#pragma GCC diagnostic pop
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <ctype.h>
#include <errno.h>
#include <dirent.h>
#include <string.h> // for memcpy
#include "dso-meta.h" // includes link.h
#include "systrap.h"
#include "vas.h"
#include "trace-syscalls.h" // FIXME: move us out of example/ into src/

int openat(int dirfd, const char *pathname, int flags, ...);
int open(const char *pathname, int flags, ...);
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
void replacement_ ## name (struct generic_syscall *s, post_handler *post) __attribute__((visibility("hidden"))); \
void replacement_ ## name (struct generic_syscall *s, post_handler *post) \
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
#define bootstrap_proto(n) __attribute__((visibility("hidden"))) n ## _ret_t  bootstrap_ ## n( n ## _args (expand_name_and_type, comma) )
// count argv entries, not including terminator
#ifdef CHAIN_LOADER
#include "chain.h"
static unsigned argv_count(char *const *argv)
{
	unsigned n = 0;
	while (*argv++) ++n;
	return n;
}

/* For some reason this doesn't always inline, so we need to macroify it. */
// static char **(__attribute__((always_inline)) realloca_argv_with_prefix)(
//	char *const *argv, char *const *pre_argv
//)
#define realloca_argv_with_prefix(argv, pre_argv) \
({ \
	unsigned count = argv_count(argv); \
	unsigned n_pre = argv_count(pre_argv); \
	char **new_argv = alloca((argv_count(argv) + n_pre + 1) * sizeof (char*)); \
	memcpy(new_argv, pre_argv, n_pre * sizeof (char*)); \
	memcpy(new_argv + n_pre, argv, (count + /* include NULL */ 1) * sizeof (char*)); \
	/*return*/ new_argv; \
})

#define PROC_BUF_SZ(longest_pid, longest_fd) \
     sizeof "/proc/" #longest_pid "/fd/" #longest_fd

/* To expand argv across #!-lines and the like, we want to
 * be careful about race conditions. One rule of thumb is
 * never to open the same file twice... so if we open a file
 * and then want to exec it, exec /proc/self/fds/n instead,
 * and use '*at()' calls so that relative paths are resolved
 * consistently. Probably we want *always* to exec something
 * in /proc/self/fds/n, because there will be some binary
 * formats the kernel is happy to execute but we don't want
 * to, at least not without warning, because if they're not
 * ELF then we can't chain-load them and won't provide whatever
 * added value our client is there for.
 *
 * When we exec something under /proc, we leave its "real" name
 * in argv[0].
 *
 * Some special cases we can easily support:
 *
 * non-ELF files that are registered with binfmt-misc
 *
 * non-ELF files whose format we recognise: run them with /bin/sh
 * ...
 * an empty file: we just run this with /bin/sh, no special case
 */

int recursively_resolve_elf_and_execveat(
   int dirfd, const char *filename,
   char *const *argv, char *const *envp
)
{
	if (0 != strcmp(filename, argv[0]))
	{
		debug_printf(1, "execing inconsistent filename and argv[0]: \"%s\" vs \"%s\"\n",
			filename, argv[0]);
	}
	int fd = openat(dirfd, filename, O_RDONLY);
	if (fd == -1) return -ENOENT;
	/* We snarf the proc-based filename of the thing we opened, because
	 * it is an actually race-free identifier for that thing. We will
	 * substitute it later. */
	unsigned sz = PROC_BUF_SZ(self, INT_MAX);
	char proc_filename_buf[sz];
	//int ret = snprintf(proc_filename_buf, sz, "/proc/%d/fd/%d", getpid(), fd);
	int ret = snprintf(proc_filename_buf, sz, "/proc/self/fd/%d", fd);
	assert(ret > 0);
	/* From now on, we use only the proc-resolved names, except for being friendly. */
	const char *friendly_filename __attribute__((unused)) = filename;
	char *const *friendly_argv  __attribute__((unused)) = argv;
	filename = proc_filename_buf;
	char *hacked_argv_head[] = {
		proc_filename_buf, // e.g. "/proc/self/fd/NN" where fd NN is a shell script
		NULL
	};
	char **hacked_argv = realloca_argv_with_prefix(
		argv + 1, hacked_argv_head
	);
	{
	char *const *argv = hacked_argv;
	// is it an ELF file?
	char eident[EI_NIDENT];
	char *pos = eident;
	ssize_t nread;
	while (-1 != (nread = read(fd, pos, sizeof eident - (pos - eident))))
	{
		pos += nread;
		if (nread == 0) break; // EOF
		if (nread == sizeof eident)
		{
			if (0 == memcmp(eident, "\177ELF", 4))
			{
				// we got an ELF file, so let's try
				char *elf_prefix_argv[] = {
					OUR_LDSO_NAME,
					NULL
				};
				char **new_argv = realloca_argv_with_prefix(
					argv, elf_prefix_argv
				);
				assert(0 == strcmp(new_argv[0], OUR_LDSO_NAME));
				/* We don't *have* to set argv[0] equal to filename...
				 * it's supposed to be "what the program thinks it's called",
				 * so do a sneaky switcheroo. Though hmm, this creates
				 * a bogus overall command line, e.g.

				 ["./truemk", "/proc/self/fd/6", "-qf", "/proc/self/fd/5"]

				 * ... because './truemk' is standing in for OUR_LDSO_NAME.
				 * Is this really adding value anywhere? I guess tools like
				 * 'ps' like to use argv[0]? If so we could make it say
				 * things like 'truemk [interpreted]' ? exename will point
				 * to the interpreter and the rest of argv will make up
				 * a sane invocation. Not all process-introspecting clients
				 * will know how to decode this, of course, so this may be
				 * too cute. We ourselves use argv[0] when we should perhaps
				 * use exename... the former has the benefit that it's in the
				 * address space, whereas exename may need a readlink(). */
				// FIXME: we could perhaps record the number of arguments
				// that come from interpreters, vs the program itself
				// e.g. above would be 3, because program's args start after
				// "/proc/self/fd/5" (and happen to be empty, here).
				// Then make it say "[interpreted 3]" or whatever.
				// NOTE: on startup, it's tempting to say: when we see a
				// /proc/self/fd/NN argument, that we're sure was put there by
				// us, to rewrite it (assuming it readlinks to a named file).
				// But that's bad! The whole point of passing the fds is that
				// it should see the same file we saw (not just file name).
				// THOUGH I guess it only matters if we do some
				// access-control-style checks on those files and so care
				// about avoiding races... otherwise probably benign.
				char *fake_argv0 = friendly_argv[0];
				char *found;
				if (NULL != (found = strrchr(fake_argv0, '/')))
				{
					const char to_append[] = " [interpreted]";
					unsigned sz = strlen(found+1) + sizeof to_append + 1;
					char *buf = alloca(sz);
					buf[0] = '\0';
					strcat(buf, found+1);
					strcat(buf, to_append);
					fake_argv0 = buf;
				}
				new_argv[0] = fake_argv0;
				return syscall(/*__NR_execveat*/ 358, dirfd,
					/* filename is always us */ OUR_LDSO_NAME, new_argv, envp, 0);
			}
		}
	}
	assert(pos <= &eident[EI_NIDENT]);
	// if we got here, it's not an ELF file, but...
	if ((pos - eident) >= 3 && 0 == memcmp(eident, "#!", 2))
	{
		// it's telling us the interpreter to use
		// we need to read a whole line, maybe longer than the ELF ident
		char *buf = eident;
		unsigned bufsz = EI_NIDENT;
		char *newlinepos = &buf[2] - 1;
		ssize_t nread = EI_NIDENT;
		/* pos <= &eident[EI_NIDENT] , and is the furthest that we've read. */
		// search forwards, growing the buffer
		// and filling it from the file as necessary
		while (*++newlinepos != '\n')
		{
			if (newlinepos == pos)
			{
				// run out of chars read, but have we run out of buffer?
				if (pos == buf + bufsz)
				{
					// grow the buffer
					char *newbuf = alloca(4 * bufsz);
					bufsz *= 4;
					memcpy(newbuf, buf, pos - buf);
					pos = newbuf + (pos - buf);
					newlinepos = newbuf + (newlinepos - buf);
					buf = newbuf;
				}
				// read into the space
				assert(pos < buf + bufsz);
				nread = read(fd, pos, bufsz - (pos - buf));
				if (nread == 0)
				{
					// we hit EOF before we found a newline, so it's not a valid #! file
					goto not_hashbang;
				}
				// OK, the extent of our valid read buffer has grown
				pos += nread;
				assert(newlinepos < pos);
			}
		}
		assert(newlinepos);
		assert(newlinepos < pos);
		assert(*newlinepos == '\n');
		// now we've found a newline; also need to word-split the #! line
		// Linux only permits one argument here, so it's a bit easier
		char *execfnpos = buf + 2;
		// skip over space between "#!" and the filename
		while (isspace(*execfnpos)) { ++execfnpos; assert(execfnpos < pos); }
		char *argpos = execfnpos;
		// now search forward for an actual space, or newline
		while (!isspace(*argpos)) { ++argpos; assert(argpos < pos); }
		assert(isspace(*argpos));
		if (argpos != newlinepos)
		{
			// we found a space after the exec filename and before the newline
			char *notspacepos = argpos;
			while (isspace(*notspacepos) && *notspacepos != '\n')
			{ ++notspacepos; assert(notspacepos < pos); }
			if (*notspacepos != '\n')
			{
				// we found an arg -- clobber the data to ensure termination
				argpos = notspacepos;
				char *arg_endpos = argpos;
				while (!isspace(*arg_endpos)) ++arg_endpos;
				*arg_endpos = '\0';
			}
			else
			{
				// there was no arg
				argpos = newlinepos;
			}
		}
		// else we didn't really find a space after the filename
		unsigned max_filename_len = argpos - execfnpos;
		char interp_filename[max_filename_len + 1 /* terminator */];
		memcpy(interp_filename, execfnpos, argpos - execfnpos);
		char *execfn_endpos = argpos;
		// can safely step backwards -- will hit '#!' before start of buffer
		while (isspace(*(execfn_endpos - 1))) --execfn_endpos;
		interp_filename[execfn_endpos - execfnpos] = '\0';

		char *prefix[] = {
			interp_filename, // snarfed from the file
			(argpos && argpos != newlinepos) ? argpos : NULL,
			NULL
		};
		// The interpreters prefix is what we previously accumulated.
		// We just expanded that with the desired interpreter filename...
		// ... read from the file itself. So far, so filenamey.
		char **new_argv = realloca_argv_with_prefix(
			argv, prefix
		);
		char *new_filename = new_argv[0];
		// HACK-y idea: put the friendly name in argv[0].
		// CARE: will this end up in an argv[1] or later position,
		// where it's not valid... maybe? NO if we get things right,
		// because we'll take the filename from 'filename', not argv[0]
		new_argv[0] = friendly_argv[0];
		return recursively_resolve_elf_and_execveat(
			dirfd, new_filename,
			new_argv, envp
		);
	}
not_hashbang:
	// if we got here, it's not an ELF file and not '#!'
	// FIXME: try the registered binfmt-misc handlers
	return -ENOEXEC;
	/* NOTE: I was wondering how to get the behaviour of running a file
	 * as a shell script when it has no hash-bang and is not a recognised
	 * binary format... since that turns *any file* into something we can
	 * try running using the /bin/sh interpreter, making ENOEXEC useless.
	 * But I believe that this behaviour is actually implemented by the
	 * shell, not by execve(), and is tried precisely when execve returns
	 * -ENOEXEC. So we don't need to emulate that here. */
	} // end argv fake-block
}

#define execve_ret_t int
#define execve_args(v, sep) \
    v(const char *, filename, 0) sep   v(char *const *, argv, 1) sep \
    v(char *const *, envp, 2)
bootstrap_proto(execve)
{
	int dirfd = open(".", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
	return recursively_resolve_elf_and_execveat(
		dirfd, filename,
		argv, envp
	);
}
REPLACE(execve)

#define execveat_ret_t int
#define execveat_args(v, sep) \
    v(int, dirfd, 0) sep  v(const char *, filename, 1) sep \
    v(char *const *, argv, 2) sep  v(char *const *, envp, 3)
bootstrap_proto(execveat)
{
	return recursively_resolve_elf_and_execveat(
		dirfd, filename,
		argv, envp
	);
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
		char buf[PROC_BUF_SZ(PID_MAX_LIMIT, INT_MAX)];
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
