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
// #include <stdatomic.h> // musl lacks this?! our old version, anyhow
#include <string.h> // for memcpy
#include "dso-meta.h" // includes link.h
#include "systrap.h"
#include "vas.h"
#include "trace-syscalls.h" // FIXME: move us out of example/ into src/
#include "chain-ext.h"
#include "relf.h"

// FIXME: put this in a header
extern const char *ldso_names[];

int openat(int dirfd, const char *pathname, int flags, ...);
int open(const char *pathname, int flags, ...);
/* Replacement syscalls for
 *
 * - in-process/image bootstrapping of instrumentation
 *         (mmap, mmap2?, mremap, munmap)
 * - cross-process/image bootstrapping via execve() rewriting
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
long replacement_ ## name (struct generic_syscall *s) __attribute__((visibility("hidden"))); \
long replacement_ ## name (struct generic_syscall *s) \
{ \
	name ## _args(init_from_generic, ;); \
	name ## _ret_t ret = bootstrap_ ## name( name ## _args(expand_name, comma), s->site ); \
	if (__systrap_post_handling) __systrap_post_handling(s, (uintptr_t) ret); \
	fixup_sigframe_for_return(s->saved_context, (long) ret, \
	    trap_len(&s->saved_context->uc.uc_mcontext), NULL); \
	return (long) ret; \
} \
WRAP_GENERIC_AS_RAW(replacement_ ## name); \
__asm__( ".pushsection __replaced_syscalls,\"aw\", @progbits\n"\
  ASMPTR " " stringifx(expand(__NR_ ## name)) "\n"\
  ASMPTR " __raw_replacement_" #name "\n"\
  ".popsection\n"\
);
#define bootstrap_proto(n) \
__attribute__((visibility("hidden"))) \
n ## _ret_t  bootstrap_ ## n( n ## _args (expand_name_and_type, comma), void *caller )

#ifdef CHAIN_LOADER
#include "chain.h"

/* FIXME: we don't want chain and preload versions of this file. Our Makefile
 * doesn't build two different versions, so that's already broken. Which version
 * does it build? The chain loader version.
 * What to do?
 * In the preload case, currently we just trap all the loaded stuff at startup
 * and don't worry about dynamically loaded things, later mmaps, etc.
 * That's probably fine for now, since the chain loader is the more "serious"
 * implementation.
 */

// count argv entries, not including terminator
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

#ifndef __NR_execveat
#if defined(__i386__)
#define __NR_execveat 358
#elif defined(__x86_64__)
#define __NR_execveat 322
#else
#error "Unknown architecture and no __NR_execveat"
#endif
#endif

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
				/* argv[0] is supposed to be "what the program thinks it's called"
				 * and doesn't have to be set equal to filename... so it's
				 * tempting to do a sneaky switcheroo to avoid argv[0] being
				 * the chain loader binary name. This may help tools like
				 * 'ps' that like to use argv[0]. However, this creates
				 * a bogus overall command line, e.g.

				 ["./truemk", "/proc/self/fd/6", "-qf", "/proc/self/fd/5"]

				 * ... because './truemk' is standing in for OUR_LDSO_NAME.
				 * Is this really adding value anywhere? We could make it say
				 * things like 'truemk [interpreted]'? exename will point
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
				// we know we got an ELF file, so let's try
				char *elf_prefix_argv[] = {
					(char*) ldso_names[(int) eident[EI_CLASS]],
					NULL
				};
				char **new_argv = realloca_argv_with_prefix(
					argv, elf_prefix_argv
				);
				assert(0 == strcmp(new_argv[0], ldso_names[(int) eident[EI_CLASS]]));
				new_argv[0] = fake_argv0;
				return syscall(__NR_execveat, dirfd,
					/* filename is always us */ ldso_names[(int) eident[EI_CLASS]], new_argv, envp, 0);
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

#ifdef __x86_64__
/* lcall-based instrumentation: whenever we map a stack,
 * map it in the lower 32 bits. */
static void tweak_flags(int *p_flags)
{
	if (    (*p_flags & MAP_GROWSDOWN)
		&& !(*p_flags & MAP_FIXED))
	{
		*p_flags |= MAP_32BIT;
		write_string("tweaked a stack mapping!\n");
	}
}
#endif

static char *fd_to_name(int fd, char *buf, size_t bufsz)
{
	unsigned readlink_target_bufsz = sizeof "/proc/self/fd/" stringifx(INT_MAX); /* MAX_FD can be -1 */
	char readlink_target_buf[readlink_target_bufsz];
	int ret = snprintf(readlink_target_buf, readlink_target_bufsz,
			"/proc/self/fd/%d", fd);
	assert(ret < readlink_target_bufsz); // else might not be nul-term'd
	ssize_t nread = readlink(readlink_target_buf, buf, bufsz-1 /* for NUL */);
	if (nread <= 0) return NULL; // something very strange going on
	buf[nread] = '\0'; // readlink() requires NUL termination ourselves
	return buf;
}

#ifdef __i386__
#if defined(__linux__) && !defined(__NR_mmap2)
#define __NR_mmap2 192
#endif
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
	/* "Wraparound loading" / "tying the knot": if we are being
	 * called by the dynamic loader and it is trying to map *us*,
	 * we should give it back the mapping that already exists.
	 *
	 * Q. How do we get the caller? Only our enclosing 'replacement'
	 * knows this at present.
	 * A. Thread it through to all bootstrap_* protos. DONE.
	 *
	 * Q. How do we tell that the caller is within the real ld.so?
	 * A. Keep a record of the lowest and highest segments that we map...
	 * maybe as a lowest/highest vaddr in the loadee_info, which we make
	 * into a global variable.
	 *
	 * Q. How do we tell that the mapping is of us?
	 * A. This is trickiest. We could track all open() calls, and any other
	 * call that can yield a memory-mappable file descriptor. Or we could
	 * do a readlink() on the fd, for mappings made by the ld.so. This adds
	 * inefficiency on every mapping made by the ld.so. Perhaps if we gate
	 * this on whether we've "seen enough", i.e. whether the wraparound link map
	 * entry is already created and RT_CONSISTENT? We should only readlink() if
	 * (0) the caller is the ld.so, and
	 * (1) we don't have the wraparound link map global variable yet, and
	 * (2) the link map's state is RT_ADD, and
	 * (3) the wraparound link map is present on a walk from _r_debug.
	 * The ld.so first maps the executable, then XXX walk through this.
	 */
	if ((uintptr_t) caller >= load_ctxt.loadee->base_addr
		&& (uintptr_t) caller < load_ctxt.loadee->base_addr + load_ctxt.loadee->max_vaddr
		&& 0 != (flags & MAP_PRIVATE))
	{
		if (!wraparound_link_map)
		{
			/* Q. How do we initialize "wraparound link map"?
			 * A. Use a constructor? TODO: add this, otherwise we will
			 * be slower than necessary. */
			struct r_debug *r_debug = find_r_debug();
			if (r_debug->r_map && r_debug->r_state == RT_ADD)
			{
				if (fd == -1)
				{
					/* This could still be relevant -- an anonymous zeroed mapping
					 * to fill in the memsz>filesz area. It would come with MAP_FIXED if so. */
					if (0 == (flags & MAP_FIXED)) goto not_wraparound;
				}
				else
				{
					size_t bufsz = 1 + strlen(our_canonical_loader_path);
					char buf[bufsz];
					char *out = fd_to_name(fd, buf, bufsz);
					if (!out || 0 != strncmp(out, our_canonical_loader_path, bufsz))
					{
						// the mapping isn't us after all
						goto not_wraparound; //break;
					}
				} /* end else fd != -1 */

				/* The caller really is mapping us, and it really is the
				 * dynamic linker. Return the corresponding offset within our mappings.
				 * TODO: permission check. */
				for (ElfW(Phdr) *phdr = load_ctxt.our_phdrs;
						         phdr != load_ctxt.our_phdrs + load_ctxt.our_nphdr;
						         ++phdr)
				{
					if (phdr->p_type == PT_LOAD)
					{
						if (fd == -1)
						{
							assert(flags & MAP_FIXED); // we tested for this earlier
							/* This could still be relevant -- an anonymous zeroed mapping
							 * to fill in the memsz>filesz area. It would come with MAP_FIXED if so,
							 * and would be mapping at the rounded-*up*-to-page position
							 * of the "filesz/memsz boundary". */
							void *addr_matching_mapping_addr = ROUND_UP_PTR_TO_PAGE((void*) (
								(intptr_t) load_ctxt.our_load_address
									+ phdr->p_vaddr + phdr->p_filesz
							));
							if (addr == addr_matching_mapping_addr) return addr;
							continue; /* It might be just some other anonymous mapping,
									   * or it might filesz/memsz-match a later phdr. */
						}
						else
						{
							/* Remember offset is the start offset of the mapping, in file space.
							/* If 'offset' is below the start of the actual data, owing to
							 * rounding, we may get a negative number for its corresponding vaddr. */
							intptr_t offset_space_distance_to_segment_start =
									(intptr_t) phdr->p_offset - (intptr_t) offset;
							intptr_t mapped_vaddr_possibly_negative = phdr->p_vaddr -
									offset_space_distance_to_segment_start;
							void *addr_matching_mapping_addr = (void*) (
								(intptr_t) load_ctxt.our_load_address + mapped_vaddr_possibly_negative
							);
							/* What mappings by the ld.so of us do we allow? We are at risk
							 * of overfitting to glibc's ld.so behaviour, but we have to
							 * approximate reasonably.
							 * If the loader is not requesting a particular address,
							 * we allow it to match any phdr for which we can find a
							 * starting address corresponding to a mapped offset. This
							 * corresponds to glibc's initial "one big mapping" behaviour
							 * that reserves the address space for the entire DSO. */
							if (!addr &&
									phdr->p_filesz > 0 &&
									offset + offset_space_distance_to_segment_start
									== phdr->p_offset)
							{
								// OK, just return the vaddr corresponding to this offset
								if (flags & MAP_FIXED)
								{
									assert(addr_matching_mapping_addr == addr);
								}
								return addr_matching_mapping_addr;
							}
							/* Otherwise, we need to make sure we match the *right* segment.
							*
							 * Subtle: don't test whether the *start* position (offset) of
							 * the mapping falls within this phdr's offset space. The start
							 * position of the *next* segment's mapping may easily do so, because
							 * we have to round down the offset to a page boundary. Instead:
							 *
							 * Test the adjusted start offset. We can test for an exact match.
							 * However, this will still fire for an earlier segment, if our
							 * mapping start offset also falls within its offset range.
							 *
							 * Also test the end of our mapping. Specifically, test the first
							 * byte of the last full page of the mapping, i.e. we should not
							 * be mapping beyond filesz, rounded up.
							 *
							 * Very short mappings are a degenerate case that may lead to
							 * assertion failures unless we refine this, i.e. can concoct
							 * an ELF file where a later phdr lives entirely within the
							 * offset space mapped by an earlier phdr. Those cases are ambiguous!
							 * So we had better craft our own binary not to include them.
							 *
							 * Filter out segments with no file data (clearly irrelevant). */
							intptr_t mapping_last_full_page_first_byte_offset
							 = offset + (length & ~((1ul<<LOG_MIN_PAGE_SIZE)-1)) - MIN_PAGE_SIZE + 1;
							assert(mapping_last_full_page_first_byte_offset > 0);
							if (phdr->p_filesz > 0 &&
								offset + offset_space_distance_to_segment_start == phdr->p_offset)
							{
								// we *could* match this one, but is it the right one?
								if (mapping_last_full_page_first_byte_offset >= phdr->p_offset &&
									mapping_last_full_page_first_byte_offset
									< ROUND_UP_PTR_TO_PAGE(phdr->p_offset + phdr->p_filesz))
								{
									// OK, just return the vaddr corresponding to this offset
									if (flags & MAP_FIXED)
									{
										assert(addr_matching_mapping_addr == addr);
									}
									return addr_matching_mapping_addr;
								}
								/* warn on the near miss, to help debugging */
								debug_printf(0, "near miss phdr matching offset %08lx len %08lx: po %08lx fz %08lx pv %08lx\n",
									(long) offset, (long) length,
									(long) phdr->p_offset, (long) phdr->p_filesz, (long) phdr->p_vaddr);
							}
						}
					} // end if PT_LOAD
				} // end for phdr
				if (fd != -1)
				{
					/* If we got here, something strange is afoot... the ld.so is making
					 * a mapping of us, but at an offset that doesn't overlap any phdr.
					 * In principle, it is allowed to, but more likely, some of the above
					 * logic is wrong. Let's play it safe. */
					assert(0 && "wraparound is fine, but ld.so should not make "
						"strange mappings of the chain loader");
					abort();
				}
			} // end if we have r_map and state is RT_ADD
		} // end if we have no wraparound_link_map yet
	} // end if caller is ld.so
not_wraparound:
	/* HACK for debugging: the program is not allowed to map us except along the
	 * wraparound path. It is almost certainly a sign of the wraparound logic above
	 * being incomplete w.r.t. some dynamic linker behaviour. (Our own librunt is
	 * allowed to, but it should not be coming down this code path.) */
#ifndef NDEBUG
	if (fd != -1)
	{
		size_t bufsz = 1 + strlen(our_canonical_loader_path);
		char buf[bufsz];
		char *out = fd_to_name(fd, buf, bufsz);
		assert(!out || 0 != strncmp(out, our_canonical_loader_path, bufsz));
	}
#endif
	tweak_flags(&flags);
	if (!(prot & PROT_EXEC))
	{
		void *ret = mmap(addr, length, prot, flags, fd, offset);
		if (ret != MAP_FAILED) replace_vperms_over(ret, (void*)((uintptr_t)ret + length), /* drop 'em */ -1);
		return ret;
	}
	// else...
	// always map writable, non-executable
	// FIXME: now that we defer the rewriting of syscall instructions, this feels dangerous...
	// should really leave out PROT_WRITE, then re-mprotect when we're doing the rewrite
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
		//struct vperm_range *added = add_vperm_range(mapping, length, prot);
		//if (!added) abort();
		replace_vperms_over(mapping, (void*)((uintptr_t) mapping + length), prot);
	}
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
	return bootstrap_mmap2(addr, length, prot, flags, fd, offset / page_size, caller);
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
	/* Check whether this intersects with any vperm range. We may have to
	 * do surgery on them if it does. What's the right logic?
	 * We could simply
	 * - do the mprotect, dropping X
	 * - delete existing vperms over any intersecting range
	 * - set the X-including vperm over the affected range.
	 * I think this works?! */
	int ret;
	if (!(prot & PROT_EXEC))
	{
		// not executable
		ret = mprotect(addr, len, prot);
		if (ret != 0) return ret; // nothing changed

		replace_vperms_over(addr, (void*)((uintptr_t) addr + len), /* drop 'em */ -1);
		return ret;
	}
	// so now it's definitely executable...
	// if the caller has asked for both writable and executable... that's not supported yet.
	if (prot & PROT_WRITE) abort();
	/* If hitting this abort ^^^ in a wraparound loader context, check you have PT_GNU_STACK phdr
	 * and if not, look for rogue assembly files lacking section .note.GNU-stack.
	 * Of course, in general we simply fail to load binaries that declare themselves as
	 * needing executable stack, and that's not good... we should implement RWX vperms. */

	/* Defer adding the execute permission until our segfault handler. */
	ret = mprotect(addr, len, prot & ~PROT_EXEC);
	if (ret != 0) return ret;
	replace_vperms_over(addr, (void*)((uintptr_t) addr + len), prot);
	return ret;
}
REPLACE(mprotect)

#if 0
/* mremap doesn't change permissions, so I think we don't need to intercept it? */
#define mremap_ret_t void *
#define mremap_args(v, sep) \
    v(void *, old_address, 0) sep   v(size_t, old_size, 1) sep \
    v(size_t, new_size, 2) sep      v(int, flags, 3) sep \
    v(void *, new_address, 4)
bootstrap_proto(mremap)
{
	if (!((flags & PROT_WRITE) && (flags & PROT_EXEC))) // XXX: these are not real mremap flags!!!
	{
		return mremap(old_address, old_size, new_size, flags, new_address);
	}
	// else... FIXME
	return mremap(old_address, old_size, new_size, flags & ~PROT_EXEC, new_address);
}
REPLACE(mremap)
#endif

#define munmap_ret_t int
#define munmap_args(v, sep) \
    v(void *, addr, 0) sep   v(size_t, length, 1)
bootstrap_proto(munmap)
{
	int ret = munmap(addr, length);
	/* If we have virtual permissions for the unmapped area, delete them. */
	if (ret == 0) replace_vperms_over(addr, (void*)((uintptr_t) addr + length), -1);
	return ret;
}
REPLACE(munmap)

/* FIXME: we need to do some stuff around processes which attempt to
 * - install a SIGILL handler
 * - mask SIGILL
 * - wait for a SIGILL (they should not see one that we generate)
 * - create a signalfd that can accept a SIGILL (but I don't think signalfd supports this?)
 */
/* Or more generally....
 *
 * Is there a clean way to take control of all incoming signals, and
 * then re-dispatch them? i.e. the analogous thing to what we do with
 * system calls. We cannot use signalfd because we still want signals
 * to be raised/raisable asynchronously.
 *
 * We could try to install a handler for all signals, but that still
 * does not prevent certain system calls from interfering e.g. using
 * signalfd, or changing the signal mask.
 *
 * We could relax about the latter on the grounds that we should be
 * able to move away from SIGILL to trampolines. So any incoming signal
 * would be bona fide. But we still want to know about them!
 *
 * Try reading what Rust's signal_hook does. It seems to use an underlying
 * "signal registry" library. As usual, it works only if the whole process
 * buys in to installing its signal handlers through this registry layer.
 * We are in a position to do better because we can trap the signal-installing
 * system calls.
 */

struct __asm_sigaction;
int rt_sigaction(int, const struct __asm_sigaction *, struct __asm_sigaction *);

static int do_sigaction_alike_call(int signum, const struct __asm_sigaction *act,
		struct __asm_sigaction *oldact,
		int (*raw_call)(int, const struct __asm_sigaction *, struct __asm_sigaction *))
{
	/* "can also  be used to check whether a given signal is valid for the current machine
	 * by calling it with NULL second and third arguments */
	if (!act && !oldact) return raw_call(signum, NULL, NULL);
	if (signum == SIGILL
#define USE_VPERMS /* FIXME: use this consistently and pervasively */
#ifdef USE_VPERMS
		|| signum == SIGSEGV
#endif
	)
	{
		/* "can be called with a NULL second argument to query the current signal handler" */
		if (!act)
		{
			/* pretend there's no handler */
			bzero(oldact, sizeof *oldact);
			return 0;
		}
		/* else the caller is actually trying to set a new handler */
		debug_printf(0, "Blocked program's attempt to install a %s handler\n",
				(signum == SIGILL) ? "SIGILL" : "SIGSEGV");
		return -1;
	}
	if (!act)
	{
		/* "can be called with a NULL second argument to query the current signal handler" */
		return raw_call(signum, NULL, oldact);
	}
	assert(act);
	struct __asm_sigaction realact;
	memcpy(&realact, act, sizeof realact);
	if (realact.sa_mask & (1<<(SIGILL-1)))
	{
		realact.sa_mask &= ~(1<<(SIGILL-1));
		debug_printf(0, "Blocked program's attempt to a signal handler that runs with SIGILL blocked\n");
	}
#ifdef USE_VPERMS
	if (realact.sa_mask & (1<<(SIGSEGV-1)))
	{
		realact.sa_mask &= ~(1<<(SIGSEGV-1));
		debug_printf(0, "Blocked program's attempt to a signal handler that runs with SIGSEGV blocked\n");
	}
#endif
/* There is no rt_sigaction wrapper, so... maybe we should raw_syscall it?
 * NOTE that our raw_ wrapper supplies the fourth argument (sigsetsize) as sizeof (__asm_sigset_t) */
	return raw_call(signum, &realact, oldact);
}
#define rt_sigaction_ret_t int
#define rt_sigaction_args(v, sep) \
    v(int, signum, 0) sep  v(const struct __asm_sigaction *, act, 1) sep \
    v(struct __asm_sigaction *, oldact, 2)
bootstrap_proto(rt_sigaction)
{
	return do_sigaction_alike_call(signum, act, oldact, raw_rt_sigaction);
}
REPLACE(rt_sigaction)

#if defined(__i386__)
struct sigaction;
int sigaction(int, const struct sigaction *, struct sigaction *);
#define sigaction_ret_t int
#define sigaction_args(v, sep) \
    v(int, signum, 0) sep  v(const struct sigaction *, act, 1) sep \
    v(struct sigaction *, oldact, 2)
bootstrap_proto(sigaction)
{
	return do_sigaction_alike_call(signum, act, oldact, sigaction);
}
REPLACE(sigaction)
#endif
