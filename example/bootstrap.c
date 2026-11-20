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
#include "bitmap.h"

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

static bitmap_word_t used_low4gb_pages[
	((1ull << 32) >> LOG_MIN_PAGE_SIZE) / (8 * sizeof (bitmap_word_t))
];
static _Bool inited_low4gb_bitmap;
static void ensure_inited_low4gb_bitmap(void)
{
	/* We need to set some areas as unusable a.k.a. already "used".
	 * - initial stack, just above 2GB
	 * - below MMAP_MIN
	 */
	if (__builtin_expect(!inited_low4gb_bitmap, 0))
	{
		memset(used_low4gb_pages, 0xff, (MMAP_MIN >> LOG_MIN_PAGE_SIZE) / 8);
		memset(used_low4gb_pages
			 + ((LOW_STACK_TOP - LOW_STACK_SIZE) >> LOG_MIN_PAGE_SIZE) / (8 * sizeof (bitmap_word_t)),
			0xff,
			(LOW_STACK_SIZE >> LOG_MIN_PAGE_SIZE) /  (8 * sizeof (bitmap_word_t))
		);
		inited_low4gb_bitmap = 1;
	}
}

#define NBYTES_2GB 0x80000000ul
/* %rax-relative lcall-based instrumentation: whenever we map a stack,
 * map it in the 2--4GB range. */
static _Bool tweak_stack_or_low_mmap_request(int *p_flags, void **p_addr, size_t *p_length)
{
	/* FIXME: need some locking here, on the bitmap. */
	void *old_addr = *p_addr;
	if (*p_flags & MAP_32BIT)
	{
		/* This forces Linux to put it in the bottom *2GB* of the address space.
		 * (You might think it would be 4GB, but it's 2GB.) That poses a problem
		 * for us when using lcall, because we want to take over the whole lower
		 * 2GB for our flipper area. */
		*p_flags &= ~MAP_32BIT;
		 /* XXX: on a MAP_32BIT call from the user, we silently return something
		  * in 2--4GB -- this breaks the documented contract! */
		goto force_2gb_4gb;
	}
	if ((*p_flags & MAP_FIXED)
		&& old_addr != NULL
		&& (uintptr_t) old_addr < NBYTES_2GB)
	{
		ensure_inited_low4gb_bitmap();
		/* Fixed request starting <2GB. What to do? Just check the pages are
		 * not in use, and abort otherwise. */
		for (unsigned pagenum =  (uintptr_t) old_addr               >> LOG_MIN_PAGE_SIZE;
		              pagenum != ((uintptr_t) old_addr + *p_length) >> LOG_MIN_PAGE_SIZE;
		     ++pagenum)
		{
			if (bitmap_get_l(used_low4gb_pages, pagenum))
			{
				write_string("MAP_FIXED in the low 2GB could not be satisfied, sorry\n");
				abort();
			}
		}
	}
	if ((*p_flags & MAP_GROWSDOWN) || (*p_flags & MAP_STACK))
	{
		if (*p_flags & MAP_FIXED)
		{
			assert((uintptr_t) old_addr > 0xffffffffu); // else our case above should have caught it
			/* Fixed, stack, but not low-4GB. We can't deal with this. */
			write_string("Fixed stack above 4GB is not supported, sorry; must disable lcall\n");
			abort();
		}
		/* TODO: check early on that nothing is mapped below 4GB, from /proc/self/maps
		 * TODO: catch MAP_FIXED mappings of a non-PIE executable like xterm
		 * - from then on, keep track over the lower 4GB in a simple array (somehow)
		 * TODO: check for mmap returning something <4GB from a NULL addr -- it shouldn't!
		 * TODO: we have the full complexity of mremap() etc to
		 * deal with... perhaps we can simply forbid mremap in the low 4GB.
		 *
		 * This relates to our xterm problem *and* our 'bumper' mapping, in the sense
		 * that we want to detect when an mmap is occurring from the ld.so mapping an
		 * executable. In that case we may do something different, e.g. permit it to
		 * map over the low 2GB and update our metadata.
		 *
		 * Keep a bitmap. One bit per page would mean 2^20 bits or 2^17 bytes or 2^5 pages.
		 * The bitmap records only "in use". That includes "mapped something for the user",
		 * e.g. xterm or the MAP_FIXED case above, and it also includes a flipper page where
		 * we know some %rax-relative lcall site requires that page.
		 *
		 * We considered other bitmaps, e.g. "mapped a real piece of flipper" would be another;
		 * "mapped either of the above" would be a third. However, all we really want to do
		 * is to be able to search for "free" areas.
		 *
		 * XXX: not true. In the low 2GB we also care to distinguish "used as flipper"
		 * from "used for a mapping" e.g. for a non-PIE executable.
		 */
		goto force_2gb_4gb;
	}
	// if we got here, there is nothing to tweak
	return 0;
force_2gb_4gb:
	ensure_inited_low4gb_bitmap();
	/* search for a free range in 2GB--4GB, then do a MAP_FIXED there */
	bitmap_word_t *start_word = used_low4gb_pages +
		(NBYTES_2GB >> LOG_MIN_PAGE_SIZE) / (8 * sizeof (bitmap_word_t));
	bitmap_word_t *limit = (void*)((unsigned char *) used_low4gb_pages + sizeof used_low4gb_pages);
	unsigned npages = ROUND_UP(*p_length, MIN_PAGE_SIZE) >> LOG_MIN_PAGE_SIZE;
	unsigned long found_bit_offset = bitmap_find_n_zero_l(start_word, limit, npages);
	if (found_bit_offset == -1) abort();

	write_string("tweaking a stack mapping! will request ");
	uintptr_t new_addr = NBYTES_2GB + (found_bit_offset << LOG_MIN_PAGE_SIZE);
	*p_addr = (void*) new_addr;
	write_ulong(new_addr);
	write_string("--");
	write_ulong(new_addr + *p_length - 1);
	write_string("\n");
	*p_flags |= MAP_FIXED_NOREPLACE;
	return 1;
}

__attribute__((visibility("hidden")))
void set_low_addr_in_use(void *addr)
{
	bitmap_word_t *start_word = used_low4gb_pages;
	bitmap_word_t *limit = (void*)((unsigned char *) used_low4gb_pages + sizeof used_low4gb_pages);
	bitmap_set_l(start_word, (uintptr_t) addr >> LOG_MIN_PAGE_SIZE);
}

static void tweak_stack_or_low_mmap_response(void *mapped, void *requested_addr, size_t length)
{
	if (mapped == requested_addr)
	{
		write_string("tweak successful\n");
		assert((uintptr_t) requested_addr < (1ull << 32)); // under 4GB
		/* set all the relevant bits */
		// we only ever issue page-aligned addresses
		unsigned npages = ROUND_UP(length, MIN_PAGE_SIZE) >> LOG_MIN_PAGE_SIZE;
		unsigned firstpage = (uintptr_t) mapped >> LOG_MIN_PAGE_SIZE;
		/* FIXME: we should set the bits preemptively in the pre-tweak, and then
		 * unset them in the *failure* case. With appropriate locking. If we fail
		 * with -EEXIST, then we should report what has been mapped there (to the
		 * extent that we know) because this shouldn't happen. */
		for (unsigned i = 0; i < npages; ++i)
		{
			bitmap_set_l(used_low4gb_pages, firstpage + i);
		}
	}
	else
	{
		write_string("tweaked low-4GB address ");
		write_ulong((uintptr_t) requested_addr);
		write_string(" could not be mapped MAP_FIXED_NOREPLACE, sorry (check the bitmap / races?)\n");
		/* HMM. There can be races here, currently, which might explain this -- FIXME. */
		abort();
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

static char *remembered_filename;
static void *remembered_base;
static size_t remembered_length;
static _Bool detect_fresh_elf_mapping_request(void *addr, size_t length, int prot,
	int flags, int fd, off_t offset, void *caller)
{
	if ((uintptr_t) caller >= load_ctxt.loadee->base_addr
		&& (uintptr_t) caller < load_ctxt.loadee->base_addr + load_ctxt.loadee->max_vaddr
		&& 0 != (flags & MAP_PRIVATE)
		&& fd != -1)
	{
		/* Q. How do we initialize "wraparound link map"?
		 * A. Use a constructor? TODO: add this, otherwise we will
		 * be slower than necessary. */
		struct r_debug *r_debug = find_r_debug();
		if (r_debug->r_map && r_debug->r_state == RT_ADD)
		{
			/* Is this an ELF file? */
			char bytes[4];
			ssize_t nread = pread(fd, bytes, 4, 0);
			if (nread == 4 && 0 == strncmp(bytes, "\177ELF", 4))
			{
				/* We're mapping an ELF file under RT_ADD. Check it's not
				 * already in the link map. */
				char buf[/*PATH_MAX*/ 4096];
				char *out = fd_to_name(fd, buf, /*PATH_MAX*/ 4096);
				if (!out) abort(); // no name or name too long, so it must be fresh, no?
				for (struct link_map *l = r_debug->r_map; l; l = l->l_next)
				{
					/* FIXME: strcmp is not a good enough check here. The link map name
					 * need not correspond to the /proc/self/fd name. */
					if (0 == strncmp(out, l->l_name, /* PATH_MAX */ 4096)) return 0;
				}
				/* If we got here, it seems to be fresh... but we will get *many*
				 * mapping requests for the same object, and as things are, we will
				 * say they are all fresh! The link map entry has not yet been created.
				 * How can we recognise the second mapping of a sequence? One idea
				 * is to catch where we are overlapping an existing mapping... assuming the
				 * pattern of a big "reservation" mapping followed by overlapping mappings
				 * for further segments. Perhaps not all loaders do this, though.
				 * Another might be to build up some state and catch
				 * calls to _dl_debug_state() to reset it, since that is called whenever
				 * the dynamic linker has finished the job. Requires care though: we might
				 * be mapping multiple DSOs before the call comes in.
				 *
				 * For now, let's remember a filename and an extent. We check for same-filename
				 * and overlap; in such a case it's not fresh.
				 * The single shared filename/extent is prone to races in theory; I think
				 * we are mostly protected by the ld.so's own locking, but there may be
				 * corner cases (FIXME). E.g. what if the RT_ADD is actually activity on
				 * another thread, while the first is racily mapping the same object? */
				if (remembered_filename
					&& 0 == strcmp(buf, remembered_filename)
					&& (flags & MAP_FIXED)
					&& addr
					&& (uintptr_t) addr >= (uintptr_t) remembered_base
					&& (uintptr_t) addr < (uintptr_t) remembered_base + remembered_length)
				{
					/* not fresh! matches the last-seen go-around */
					return 0;
				}
			return_fresh:
				/* Seems fresh. Remember it for future go-arounds.
				 * We will have to fill in the base and length in the caller. */
				if (remembered_filename) free(remembered_filename);
				remembered_filename = strdup(buf);
				return 1;
			}
		}
	}
	return 0;
}

static void *detect_wraparound_mapping_request(void *addr, size_t length, int prot,
	int flags, int fd, off_t offset, void *caller)
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
			/* XXX: if the ld.so is "invoked" not requested, it has to load
			 * the executable. While it does so, the link map state is RT_CONSISTENT
			 * not RT_ADD. How can we catch this case? Maybe r_map == NULL? */
			if (r_debug->r_map &&
					(r_debug->r_state == RT_ADD
					|| r_debug->r_map == NULL))
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
						goto not_wraparound;
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
									< (intptr_t) (ROUND_UP_PTR_TO_PAGE(phdr->p_offset + phdr->p_filesz)))
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

	/* HACK for debugging: the program is not allowed to map us, the chain loader,
	 * except along the wraparound path. It is almost certainly a sign of the
	 * wraparound logic above being incomplete w.r.t. some dynamic linker behaviour.
	 * (Our own librunt is allowed to, but it should not be coming down this code path.) */
not_wraparound:
#ifndef NDEBUG
	if (fd != -1)
	{
		size_t bufsz = 1 + strlen(our_canonical_loader_path);
		char buf[bufsz];
		char *out = fd_to_name(fd, buf, bufsz);
		assert(!out || 0 != strncmp(out, our_canonical_loader_path, bufsz));
	}
#endif
	return NULL;
}

/* TODO: also make "bumper" pages around each mapped lib, for %rip-relative calls/lcalls.
 * Where is the right place to allocate these? When an mmap comes in, it is hard to
 * detect a new lib is being mapped. Maybe if the fd refers to an ELF binary, place
 * the map with space for its 2GB bumpers? One way would be to artificially increase
 * the mapped size by 4GB, say, then remap immediately at a +2GB address and the
 * original size, and remap the surrounding areas similarly. Add these bumpers to the
 * lazy sigbus handling, initially; if we want to try the plain indirect call, that
 * is a separate "optimisation" (or, really, spending time for memory; note there is
 * NOT a small downward step in security because unlike e9-based patching, we don't
 * add any extra executable instructions).
 *
 * XXX: check my thinking about %rax-relative puns with controllable immediates.
 * Does it matter if our pun bytes are negative? We can load a high immediate into
 * %rax... will it be sign-extended? That's important s.t. the high (negative) pun
 * bytes are added to a negative earlier-loaded immediate value to yield a smallish
 * positive number. I am almost certain it will be sign-extended and so we are fine.
 *
 * Spending 4GB of VAS per DSO is fine normally but could cause problems... in a 48-bit
 * address space, the hard limit is 64k such DSOs. I am fine with this for now, but
 * I do know there are workloads with thousands of small DSOs.
 */

/* In i386, mmap2 is the main mmap function and we define mmap separately.
 * Otherwise, mmap is the main one. Either way, what follows is the main code. */
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
	unsigned long long offset = (unsigned long long) pgoffset * page_size;
	void *wraparound_ret = detect_wraparound_mapping_request(addr, length, prot, flags,
			fd, offset, caller);
	if (wraparound_ret) return wraparound_ret;
	if (!(prot & PROT_EXEC))
	{
		void *ret = (void*) syscall(__NR_mmap2, addr, length, prot, flags, fd, pgoffset);
		if (ret != MAP_FAILED) replace_vperms_over(ret, (void*)((uintptr_t)ret + length), /* drop 'em */ -1);
		return ret;
	}
	// else...
	// always map writable, non-executable
	// FIXME: now that we defer the rewriting of syscall instructions, this feels dangerous...
	// should really leave out PROT_WRITE, then re-mprotect when we're doing the rewrite
	int temporary_prot = (prot | PROT_WRITE | PROT_READ) & ~PROT_EXEC;
	void *mapping = (void*) syscall(__NR_mmap2, addr, length, temporary_prot, flags, fd, pgoffset);
#else
#define mmap_ret_t void *
#define mmap_args(v, sep) \
    v(void *, addr, 0) sep   v(size_t, length, 1) sep \
    v(int, prot, 2) sep      v(int, flags, 3) sep \
    v(int, fd, 4) sep        v(unsigned long, offset, 5)
bootstrap_proto(mmap)
{
	void *wraparound_ret = detect_wraparound_mapping_request(addr, length, prot, flags,
			fd, offset, caller);
	if (wraparound_ret) return wraparound_ret;

	/* Is this a PROT_NONE mapping created by the ld.so to align a smaller mapping within?
	 * If so, we have to allow space for bumpers now, because the placeholder mapping is
	 * what allocates the address space. We will handle this case a bit like a fresh ELF. */
	_Bool mapping_is_ld_so_placeholder = /*detect_ld_so_placeholder_mapping_request(addr, length, prot, flags,
			fd, offset, caller);*/
			((uintptr_t) caller >= load_ctxt.loadee->base_addr
			&& (uintptr_t) caller < load_ctxt.loadee->base_addr + load_ctxt.loadee->max_vaddr
			&& 0 != (flags & MAP_PRIVATE)
			&& 0 != (flags & MAP_ANONYMOUS)
			&& prot == PROT_NONE
			&& fd == -1);
	/* Is this mapping a new ELF? If so, we will add lcall bumpers. */
	_Bool fresh_elf = detect_fresh_elf_mapping_request(addr, length, prot, flags,
			fd, offset, caller);
	/* PROBLEM: sometimes alignment dictates that the ld.so will map a large
	 * anonymous mapping and then map the segment MAP_FIXED in its place, a
	 * small offset from the start. This won't look like a fresh ELF but it
	 * will cause us to fail later, if extending it by 4GB overlaps other
	 * mappings.
	 *
	 * Perhaps we could preemptively resize this anonymous mapping too?
	 * We do get a clue in the form of PROT_NONE, though. So perhaps we should...
	 *
	 * - if the ld.so is trying to reserve some address space with PROT_NONE,
	 *   reserve 4GB more than it asks for, add MAP_NORESERVE, and return addr+2GB.
	 *   We remember this as our "placeholder" mapping. We have at most one of these.
	 * - if a later MAP_FIXED request comes in with a fresh ELF, we will naturally
	 *   map over it with our bumpers, *as long as* we know *not* to add
	 *   MAP_FIXED_NOREPLACE to the flags in such a case.
	 * - if the next fresh ELF that comes in does *not* use the placeholder, we
	 *   drop it. i.e. we have at most one placeholder at a time.
	 */
	static void *placeholder_adjusted_base;
	static size_t placeholder_adjusted_length;
	static _Bool placeholder_used;

	size_t orig_length = length;
	int orig_flags = flags;
	_Bool fresh_elf_overlaps_placeholder = 0;
	if (fresh_elf || mapping_is_ld_so_placeholder)
	{
		/* XXX: currently we remap the user-desired portion of this huge "bumpered" mapping
		 * into its mid-bumpers position, which is the address returned to the caller. That
		 * does not give us an opportunity to unset this MAP_NORESERVE flag. Perhaps we
		 * should create the final mapping by a fresh mmap rather than mremap. */
		if (fresh_elf && ((flags & MAP_FIXED) || (flags & MAP_FIXED_NOREPLACE)))
		{
			assert(addr);
			fresh_elf_overlaps_placeholder =
			   (uintptr_t) addr >= (uintptr_t) placeholder_adjusted_base + NBYTES_2GB &&
			   (uintptr_t) addr + orig_length < (uintptr_t) placeholder_adjusted_base + placeholder_adjusted_length;

			/* XXX: what do we do with 'length' if we previously mapped a placeholder?
			 * that means we have a large PROT_NONE region, big enough for bumpers.
			 * I think we need to map over it,  */

			write_string("warning: fixed mapping requested for fresh object ");
			raw_write(2, remembered_filename, strlen(remembered_filename));
			write_string(" at ");
			write_ulong((uintptr_t) addr);
			write_string(", length ");
			write_ulong((uintptr_t) orig_length);
			if (fresh_elf_overlaps_placeholder) write_string("; it does "); else write_string("; it does not ");
			write_string("overlap known placeholder");
			if (placeholder_adjusted_base)
			{
				write_string(" from ");
				write_ulong((uintptr_t) placeholder_adjusted_base);
				write_string(" to ");
				write_ulong((uintptr_t) placeholder_adjusted_base + placeholder_adjusted_length);
				write_string("\n");
			}
			else write_string (" (no placeholder)\n");
			if ((uintptr_t) addr < (3 * NBYTES_2GB + MMAP_MIN)) abort(); // 6GB minimum

			if (!fresh_elf_overlaps_placeholder)
			{
				write_string("warning: freshly loaded ELF file being mapped MAP_FIXED for some reason\n");
				addr = (void*)((uintptr_t) addr - NBYTES_2GB); // subtract 2GB
				length = ROUND_UP(length, MIN_PAGE_SIZE) + (1ull<<32); /* add 4GB to the mapping size! */
				flags |= MAP_NORESERVE; /* it'd be a lot of swap... */
				flags |= MAP_FIXED_NOREPLACE; // we're mapping more than the caller bargained for, so safeguard against clobbering
			}
			else
			{
				/* If it overlaps a placeholder, we just map the length requested because
				 * we've already mapped the bumper space in the placeholder */
			}
		}
		else // not fresh elf (i.e. is ld.so placeholder) or not fixed mapping of fresh ELF
		{
			length = ROUND_UP(length, MIN_PAGE_SIZE) + (1ull<<32); /* add 4GB to the mapping size! */
			flags |= MAP_NORESERVE; /* it'd be a lot of swap... */
		}
	}
	/* Tweaking handles stack mappings: it ensures they are placed in the 2--4GB range. */
	_Bool tweaked = tweak_stack_or_low_mmap_request(&flags, &addr, &length);
	void *mapping;
	int temporary_prot;
	if (!(prot & PROT_EXEC)) temporary_prot = prot;
	else
	{
		// always map writable, non-executable
		// FIXME: now that we defer the rewriting of syscall instructions, this feels dangerous...
		// should really leave out PROT_WRITE, then re-mprotect when we're doing the rewrite
		temporary_prot = (prot | PROT_WRITE | PROT_READ) & ~PROT_EXEC;
	}
	mapping = mmap(addr, length, temporary_prot, flags, fd, offset);
#endif /* end of mmap2 versus mmap alternation...  */
#ifdef __x86_64__
	if (tweaked) { assert(!fresh_elf); tweak_stack_or_low_mmap_response(mapping, addr, length); }
	if ((fresh_elf || mapping_is_ld_so_placeholder) && mapping != MAP_FAILED)
	{
		void *orig_mapping = mapping;
		if (mapping_is_ld_so_placeholder)
		{
			// remember this placeholder
			placeholder_adjusted_base = mapping;
			placeholder_adjusted_length = length;
			placeholder_used = 0; // we haven't yet seen it being used
			/* for returning to the caller, pretend the extra placeholder space thing never happened */
			mapping = (void*)((uintptr_t) mapping + NBYTES_2GB);
			length = orig_length;
		}
		/* Does this mapping overlap our placeholder? */
		if (fresh_elf && !fresh_elf_overlaps_placeholder)
		{
			assert(!mapping_is_ld_so_placeholder);

			/* No, so forget about the placeholder.
			 * And unmap the parts that the ld.so didn't actually ask for, unless
			 * we have put a bumper in them. */
			if (placeholder_adjusted_base && !placeholder_used)
			{
				munmap((void*)((uintptr_t) placeholder_adjusted_base), NBYTES_2GB);
				munmap((void*)((uintptr_t) placeholder_adjusted_base + placeholder_adjusted_length - NBYTES_2GB), NBYTES_2GB);
			}
			placeholder_adjusted_base = NULL;
			placeholder_adjusted_length = 0;
			placeholder_used = 0;
		}
		if (fresh_elf)
		{
			void *prebumper_2gb_start;
			void *postbumper_2gb_start;
			if (fresh_elf_overlaps_placeholder)
			{
				/* We've mapped over the top of a placeholder. That's good. The placeholder
				 * includes space for bumpers, but not the bumpers yet. */
				mapping = addr; // this is effectively doing += 2GB thing
				assert(length == orig_length); // we did not tweak the length this time around
				prebumper_2gb_start = (void*)((uintptr_t) addr - NBYTES_2GB);
				postbumper_2gb_start = (void*)((uintptr_t) addr + ROUND_UP(orig_length, MIN_PAGE_SIZE));
				placeholder_used = 1; /* don't unmap the bumper! */
			}
			else
			{
				/* Of the entire expanse we mapped, remap the first 'length' at addr + 2GB.
				 * Then replace the first and last 2GB with a bumper mapping. */
				void *remapped
				 = mremap(mapping, ROUND_UP(orig_length, MIN_PAGE_SIZE), ROUND_UP(orig_length, MIN_PAGE_SIZE),
					MREMAP_FIXED/*|MREMAP_DONTUNMAP*/|MREMAP_MAYMOVE,
					(void*)((uintptr_t) mapping + NBYTES_2GB));
				/* FIXME: we leave the original area unmapped briefly, so this is racy... but
				 * MREMAP_DONTUNMAP only works for private anonymous mappings. */
				if (remapped == MAP_FAILED) abort();
				assert(remapped == (void*)((uintptr_t) mapping + NBYTES_2GB));
				mapping = remapped;
				length = orig_length; /* used for vperms, below */
				prebumper_2gb_start = orig_mapping;
				postbumper_2gb_start = (void*)((uintptr_t) remapped + ROUND_UP(orig_length, MIN_PAGE_SIZE));
			}
			// either way, we have to map the bumpers
			extern int bumper_fd_empty __attribute__((visibility("hidden"))); /* FIXME: goes in a header please */
			void *prebumper = mmap(prebumper_2gb_start, NBYTES_2GB, PROT_READ,
				MAP_PRIVATE|MAP_NORESERVE|MAP_FIXED, bumper_fd_empty, 0);
			if (prebumper == MAP_FAILED) abort();
			void *postbumper = mmap(postbumper_2gb_start, NBYTES_2GB, PROT_READ,
				MAP_PRIVATE|MAP_NORESERVE|MAP_FIXED, bumper_fd_empty, 0);
			if (postbumper == MAP_FAILED) abort();

			/* We remember a mapping to catch later not-so-fresh ELF requests;
			 * we remembered the filename earlier. */
			remembered_base = mapping; // not the orig mapping!
			remembered_length = orig_length;
		}
	}
#endif
	if (mapping != MAP_FAILED)
	{
		//struct vperm_range *added = add_vperm_range(mapping, length, prot);
		//if (!added) abort();
		if (!(prot & PROT_EXEC)) // this includes the placeholder PROT_NONE case
		{
			/* no need to set vperms, but we clear any that existed and are now being mapped over */
			replace_vperms_over(mapping, (void*)((uintptr_t)mapping + length), /* drop 'em */ -1);
		}
		else replace_vperms_over(mapping, (void*)((uintptr_t) mapping + length), prot);
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
#define USE_LCALL /* FIXME: use this consistently and pervasively */
#ifdef USE_LCALL
		|| signum == SIGBUS
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
				(signum == SIGILL) ? "SIGILL" : (signum == SIGSEGV) ? "SIGSEGV" : "SIGBUS");
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
#ifdef USE_LCALL
	if (realact.sa_mask & (1<<(SIGBUS-1)))
	{
		realact.sa_mask &= ~(1<<(SIGBUS-1));
		debug_printf(0, "Blocked program's attempt to a signal handler that runs with SIGBUS blocked\n");
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
struct __asm_sigaction;
int sigaction(int, const struct __asm_sigaction *, struct __asm_sigaction *);
#define sigaction_ret_t int
#define sigaction_args(v, sep) \
    v(int, signum, 0) sep  v(const struct __asm_sigaction *, act, 1) sep \
    v(struct __asm_sigaction *, oldact, 2)
bootstrap_proto(sigaction)
{
	return do_sigaction_alike_call(signum, act, oldact, sigaction);
}
REPLACE(sigaction)
#endif

int rt_sigprocmask(int how, const __asm_sigset_t *set, __asm_sigset_t *oldset, size_t setsize);
static int do_sigprocmask_alike_call(int how, const __asm_sigset_t *p_set,
    __asm_sigset_t *oldset, size_t setsize,
    int (*raw_call)(int, const __asm_sigset_t *, __asm_sigset_t *, size_t))
{
	__asm_sigset_t set;
	bzero(&set, sizeof set);
	if (p_set) set = *p_set;
	if (p_set && set & (1<<(SIGILL-1)))
	{
		set &= ~(1<<(SIGILL-1));
		debug_printf(0, "Foiling program's attempt to mask SIGILL\n");
	}
#ifdef USE_VPERMS
	if (p_set && set & (1<<(SIGSEGV-1)))
	{
		set &= ~(1<<(SIGSEGV-1));
		debug_printf(0, "Foiling program's attempt to mask SIGSEGV\n");
	}
#endif
#ifdef USE_LCALL
	if (p_set && set & (1<<(SIGBUS-1)))
	{
		set &= ~(1<<(SIGBUS-1));
		debug_printf(0, "Foiling program's attempt to mask SIGBUS\n");
	}
#endif
	return raw_call(how, p_set ? &set : NULL, oldset, setsize);
}
#define rt_sigprocmask_ret_t int
#define rt_sigprocmask_args(v, sep) \
    v(int, how, 0) sep  v(const __asm_sigset_t *, set, 1) sep \
    v(__asm_sigset_t *, oldset, 2) sep \
    v(size_t, setsize, 3)
bootstrap_proto(rt_sigprocmask)
{
	return do_sigprocmask_alike_call(how, set, oldset, setsize, raw_rt_sigprocmask);
}
REPLACE(rt_sigprocmask)

#if defined(__i386__)
int sigprocmask(int, const __asm_sigset_t *, __asm_sigset_t *);
#define sigprocmask_ret_t int
#define sigprocmask_args(v, sep) \
    v(int, how, 0) sep  v(const __asm_sigset_t *, set, 1) sep \
    v(__asm_sigset_t *, oldset, 2) sep \
    v(size_t, setsize, 3)
bootstrap_proto(sigprocmask)
{
	return do_sigprocmask_alike_call(how, set, oldset, setsize, raw_sigprocmask);
}
REPLACE(sigprocmask)
#endif
