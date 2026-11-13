/* chain-ext.c -- should only contain functions specific to the
 * chain-loader (fake ld.so) that we use for init.*/

#define _GNU_SOURCE
#include <stdio.h>
#include <assert.h>

/* sys/types.h, but working around musl's paren-light style */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wparentheses"
#include <sys/types.h>
#pragma GCC diagnostic pop

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h> // for memcpy
#include "dso-meta.h" // includes link.h
#include "donald.h"
#include "chain.h"    // from donald
#include "chain-ext.h"  // ours
#include "relf.h"
#include "systrap.h"
#include "trace-syscalls.h"

void __attribute__((visibility("protected")))
__trace_syscalls_pre_handling(struct generic_syscall *gsp);
void __attribute__((visibility("protected")))
__trace_syscalls_post_handling(struct generic_syscall *gsp, long ret);

static struct link_map temporary_link_map = {
	.l_name = "", /* XXX: set the name to something sensible? Do we want to "be the executable"? */
	.l_ld = &_DYNAMIC[0]
};
extern int _start;
#if MAPPING_MAX != 16
#error "MAPPING_MAX is not what we expected"
#endif
uintptr_t ldso_load_addr;
uintptr_t ldso_end_addr;
struct file_metadata temporary_file_metadata = {
	.filename = "",
	.load_site = &_start,
	.l = &temporary_link_map,
	.dynsym = NULL,/* always mapped by ld.so */
	.dynstr = NULL, /* always mapped by ld.so */
	.dynstr_end = NULL,
	.dynsymndx = 0, // section header idx of dynsym, or 0 if none such
	.dynstrndx = 0
};

/* The purpose of this function is to make librunt introspection work
 * before we run any guest code, including the chain-loaded dynamic
 * linker. We want our to reflect on that before it does anything, because
 * we want to trap its syscalls.
 *
 * Normally librunt links against _r_debug in order to locate the link map.
 * That won't work in this DSO, because there is no _r_debug. But librunt
 * will fall back on walking _DYNAMIC and looking for a DT_DEBUG that points
 * at the _r_debug. We can point this at the ld.so's _r_debug. PROBLEM: it
 * has not been initialized with any link map pointer yet. Rather than
 * futzing with _DYNAMIC, maybe we should instead just fake out a local
 * _r_debug? Or for good measure we could do both. It might stil be worth
 * doing the DT_DEBUG thing to make gdb less confused. And it seems like
 * less of an egregious violation of convention to have two DT_DEBUGs
 * than to have two _r_debugs. */
/* This gets called from the CHAIN_LOADER macro-inserted call in main.c...
 * see Makefile.
 */
static ElfW(Dyn) *dt_debug;
static void set_temporary_link_map(ElfW(Ehdr) *ehdr, ElfW(Shdr) *shdrs, ElfW(Phdr) *phdrs,
	uintptr_t inferior_load_addr, ElfW(Dyn) *created_dt_debug)
{
	if (!created_dt_debug) return;
	dt_debug = created_dt_debug;
	ElfW(Dyn) *found_debug = dynamic_xlookup(&_DYNAMIC[0], DT_DEBUG);
	assert(found_debug);
	assert(found_debug == created_dt_debug);
	/* In our loader's _DYNAMIC as we create it initially, the r_debug is already
	 * a pointer to the inferior ld.so's. It will never get ADJUST_DYN_INFO'd
	 * by the ld.so because that ld.so does not know that our _DYNAMIC exists. */
	struct r_debug *r = (struct r_debug *) created_dt_debug->d_un.d_ptr;
	assert(r);

	/* Now we are writing into the inferior ld.so's _r_debug.
	 * To use librunt to instrument the ld.so, librunt needs to work *before*
	 * the ld.so has initialized _r_debug's fields. librunt needs these fields!
	 * Initially we use a temporary link map that contains just us.
	 * We will clear r_map before running the real ld.so. */
	r->r_version = 0;
	r->r_map = &temporary_link_map;
	r->r_brk = (ElfW(Addr)) NULL;
	r->r_state = RT_CONSISTENT;
	/* The memory address at which the dynamic loader is loaded...
	 * the inferior one, i.e. the one actually doing the work. */
	r->r_ldbase = inferior_load_addr;
	temporary_file_metadata.ehdr = ehdr;
	temporary_file_metadata.shdrs = shdrs;
	ElfW(Addr) max_vaddr = 0;
	for (unsigned i = 0; i < ehdr->e_phnum; ++i)
	{
		ElfW(Addr) max_vaddr_this_obj = phdrs[i].p_vaddr + phdrs[i].p_memsz;
		if (max_vaddr_this_obj > max_vaddr) max_vaddr = max_vaddr_this_obj;
	}
	temporary_link_map.l_addr = ldso_load_addr = inferior_load_addr;
	ldso_end_addr = ldso_load_addr + max_vaddr;
}
static void clear_temporary_link_map(ElfW(Dyn) *created_dt_debug)
{
	assert(created_dt_debug == dt_debug); // FIXME: just eliminate this arg
	struct r_debug *r = (struct r_debug *) created_dt_debug->d_un.d_ptr;
	assert(r);
	r->r_version = 0;
	r->r_map = 0;
	r->r_brk = (ElfW(Addr)) NULL;
	r->r_state = 0 /*RT_CONSISTENT*/;
	r->r_ldbase = 0;
}

struct file_metadata *__real___runt_files_metadata_by_addr(void *addr);
struct file_metadata *__wrap___runt_files_metadata_by_addr(void *addr)
{
	if ((uintptr_t) addr >= ldso_load_addr
		 && (uintptr_t) addr < ldso_end_addr)
	{
		return &temporary_file_metadata;
	}
	struct r_debug *r = dt_debug ? (struct r_debug *) dt_debug->d_un.d_ptr : find_r_debug();
	if (r->r_map == &temporary_link_map) return NULL; // too early to safely call librunt
	return __real___runt_files_metadata_by_addr(addr);
}

// we have another special way to die
#define die(s, ...) do { debug_printf(0, s , ##__VA_ARGS__); abort(); } while(0)

#ifdef CHAIN_LOADER
/* If we're not only chaining but also wrapping around, then we should grab
 * a pointer to our own link map. This is used e.g. in bootstrap.c to avoid
 * the slow path for "knot-tying" mappings. */
struct link_map *wraparound_link_map __attribute__((visibility("hidden")));
/*  */
__attribute__((constructor))
static void init_wraparound(void)
{
	/* wraparound_link_map = dlopen(our_canonical_loader_path, RTLD_NOW|RTLD_NOLOAD); */
	/* Calling dlopen in a constructor is a dicey thing to do, in my
	 * experience with glibc's ld.so. Let's use fakery instead. */
	wraparound_link_map = get_highest_loaded_object_below(&wraparound_link_map);
	assert(wraparound_link_map);
	assert(0 == strcmp(wraparound_link_map->l_name, our_canonical_loader_path)
			|| 0 == strcmp(wraparound_link_map->l_name, our_absolute_loader_path));
}
#endif

const char *our_loader_path __attribute__((visibility("hidden")));
const char *our_absolute_loader_path __attribute__((visibility("hidden")));
const char *our_canonical_loader_path __attribute__((visibility("hidden")));
__attribute__((destructor))
static void deinit_loader_path(void)
{
	if (our_loader_path[0] != '/') free((void*) our_absolute_loader_path);
	free((void*) our_canonical_loader_path);
}

static void print_auxv(FILE *stream, ElfW(auxv_t) *p_auxv)
{
	struct auxv_limits lims = get_auxv_limits(p_auxv);
	
	fprintf(stream, "argcount: %d at %p\n", *lims.p_argcount, lims.p_argcount);
	fprintf(stream, "asciiz: %p to %p (%lu bytes)\n", lims.asciiz_start, lims.asciiz_end,
		(unsigned long) (lims.asciiz_end - lims.asciiz_start));
	
	fprintf(stream, "args:\n");
	assert(lims.arg_vector_terminator == lims.arg_vector_start + *lims.p_argcount);
	for (int i = 0; i < *lims.p_argcount; ++i)
	{
		fprintf(stream, "[%03d] (%p) %s\n", i, lims.arg_vector_start[i], lims.arg_vector_start[i]);
	}
	fprintf(stream, "\nenv:\n");
	unsigned i = 0; // new 'i'
	char **p = (char**) lims.env_vector_start;
	for (; p != (char**) lims.env_vector_terminator + 1; ++i, ++p)
	{
		fprintf(stream, "[%03d] (%p) %s\n", i, *p, *p);
	}
	assert(p == (char**) lims.env_vector_terminator + 1);
	ElfW(auxv_t) *p_e = lims.aux_vector_start;
	fprintf(stream, "\nauxv:\n");
	i = 0;
	for (; p_e != (ElfW(auxv_t)*) lims.aux_vector_terminator + 1; ++i, ++p_e)
	{
#define expand_auxv_string_tags(tag) || p_e->a_type == tag
		if (0 auxv_string_tags(expand_auxv_string_tags))
		{
			fprintf(stream, "[%03d] %08x : (%p) \"%s\" %swithin asciiz limit %p\n", i, (unsigned) p_e->a_type,
				(char*) p_e->a_un.a_val, (unsigned long) p_e->a_un.a_val,
				((char*) p_e->a_un.a_val >= lims.asciiz_start && 
					(char*) p_e->a_un.a_val < lims.asciiz_end) ? "" : "not ", lims.asciiz_end);
		}
		else
		{
			fprintf(stream, "[%03d] %08x : %lx\n", i, (unsigned) p_e->a_type,
				(long) p_e->a_un.a_val);
		}
	}
}

void __hook_pre_enter(struct chain_load_ctxt *cc)
{
	/* We are called from the chain loader's "enter" wrapper, immediately
	 * before it calls out to the "real" enter (from donald).
	 *
	 * We also snarf the section headers and pass them to set_temporary_link_map()
	 * so that librunt's section-header introspection will work even in our
	 * wacky before-real-startup chain-loader context. */
	int inferior_fd = open(cc->load->loadee_path, O_RDONLY); // HACK: re-open ld.so
	off_t newloc = lseek(inferior_fd, cc->load->loadee->ehdr.e_shoff, SEEK_SET);
	ElfW(Shdr) shdrs[cc->load->loadee->ehdr.e_shnum];
	for (unsigned i = 0; i < cc->load->loadee->ehdr.e_shnum; ++i)
	{
		off_t off = cc->load->loadee->ehdr.e_shoff + i * cc->load->loadee->ehdr.e_shentsize;
		newloc = lseek(inferior_fd, off, SEEK_SET);
		if (newloc != off) die("could not seek to section header %d (0x%x) in %s (fd %d)\n", i, (unsigned) off, cc->load->loadee_path, inferior_fd);
		size_t ntoread = (sizeof shdrs[0] < cc->load->loadee->ehdr.e_shentsize) ? sizeof shdrs[0] : cc->load->loadee->ehdr.e_shentsize;
		ssize_t nread = read(inferior_fd, &shdrs[i], ntoread);
		if (nread != ntoread) die("could not read section header %d in %s\n", i, cc->load->loadee_path);
	}
	/* */
	set_temporary_link_map(&cc->load->loadee->ehdr, shdrs,
		(void*)cc->load->loadee->phdrs_addr,
		cc->load->loadee->base_addr,
		cc->our_dt_debug);
	close(inferior_fd);

	/* What string should serve as our "canonical" path? If we were requested,
	 * it should be the .interp string. If we were invoked, it should be an
	 * absolutified-if-relative version of the invoked path. We free this in the
	 * destructor above. */
	our_loader_path = get_loader_path(cc->load);
	if (our_loader_path[0] == '/')
	{
		our_absolute_loader_path = our_loader_path;
	}
	else
	{
		char *cwd = get_current_dir_name();
		int ret = asprintf((char**) &our_absolute_loader_path, "%s/%s", cwd,
			our_loader_path + strspn(our_loader_path, "./"));
		assert(ret > 0);
		assert(our_absolute_loader_path);
		assert(our_absolute_loader_path[0] == '/');
		free(cwd);
	}
	our_canonical_loader_path = realpath(our_absolute_loader_path, NULL);
	if (!our_canonical_loader_path) abort();

	// FIXME: libsystrap isn't being init'd, so force it
	__libsystrap_force_init();

	start_tracing(p_auxv, /* apply replacements from asm block? */ 1, cc);

	// this is undoing the effect of set_temporary_link_map
	clear_temporary_link_map(cc->our_dt_debug);

	/* Tweak the environment. We want ourselves (canonically) to be the head of the 
	 * LD_PRELOAD list. Two cases: there's no LD_PRELOAD in envp, or there
	 * is. */
	/* Now ensure we have an appropriate LD_PRELOAD in place. */
	fprintf(stderr, "Initial auxv....\n");
	fflush(stderr);
	print_auxv(stderr, p_auxv);
	struct auxv_limits limits = get_auxv_limits(p_auxv);
	const char *equals_pos = NULL;
	char **found_existing_ld_preload = environ_get_env_vector_ptr("LD_PRELOAD",
		(char**) limits.env_vector_start, &equals_pos);
	char *new_ld_preload_env_string;
	unsigned env_vector_idx_to_update = -1;
	void *new_auxv_block = NULL;
	if (found_existing_ld_preload)
	{
		/* Does the found string already begin with us? If not, we need to make it so.
		 * TODO: do an identity check on the file, because funky paths with '../' can
		 * still fool us. */
		const char *preload_str = equals_pos + 1;
		size_t nbytes_first_word = strcspn(preload_str, ": "); /* matches glibc's logic */
		if ((strlen(our_absolute_loader_path) == nbytes_first_word
				&& 0 == strncmp(preload_str, our_absolute_loader_path, nbytes_first_word))
		||  (strlen(our_canonical_loader_path) == nbytes_first_word
				&& 0 == strncmp(preload_str, our_canonical_loader_path, nbytes_first_word)))
		{
			/* It's a match. We don't need to change anything. */
			goto skip_rewrite_auxv;
		}
		/* Else we have an LD_PRELOAD string but it is not what we require. Make a
		 * new one and fix up the vector entry with a pointer to the new string.
		 * To allow us to create the string in temporary heap memory, we should use the
		 * ability of copy_and_resize_auxv to add new string data as it copies, then update
		 * the vector entry. */
		env_vector_idx_to_update = found_existing_ld_preload - (char**) limits.env_vector_start;

		int ret = asprintf(&new_ld_preload_env_string, "LD_PRELOAD=%s %s",
				our_absolute_loader_path, preload_str);
		assert(ret > 0);
		/* XXX: another quirk is that if we leave the old LD_PRELOAD string in the asciiz,
		 * quick-and-dirty methods that reflect on the environment by dumping these strings
		 * will be led astray. Really we may want to completely repack the asciiz area. */
	}
	else
	{
		/* We need to add a new env vector entry, as well as the string data.*/
		int ret = asprintf(&new_ld_preload_env_string, "LD_PRELOAD=%s", our_absolute_loader_path);
		assert(ret > 0);
	}

	fprintf(stderr, "auxv after initial copy, adding/updating LD_PRELOAD (to \"%s\"):\n",
		new_ld_preload_env_string);
	size_t bytes = ((uintptr_t) limits.asciiz_end - (uintptr_t) limits.p_argcount)
		 + /* how many new vector entries? */ sizeof (char*) * ((env_vector_idx_to_update == -1) ? 1 : 0)
		 + /* how many new characters in asciiz? */ 1 + strlen(new_ld_preload_env_string)
		 + 15 /* alignment hack: worst-case padding when doing 16-byte alignment */;
	char *new_env[] = { new_ld_preload_env_string + 0 }; // may or may not be used
	new_auxv_block = malloc(bytes);
	struct auxv_copy_status status = copy_and_resize_auxv(new_auxv_block,
		p_auxv,
		&limits,
		/* n entries incl terminator */ 1 + (limits.aux_vector_terminator - p_auxv),
		/* additional_auxv_entries   */ NULL,
		/* n_env_entries_incl_terminator */ 1 + (limits.env_vector_terminator - limits.env_vector_start)
			+ ((env_vector_idx_to_update == -1) ? 1 : 0),
		/* additional_env_entries */ new_env,
		/* n_argv_entries_incl_terminator */ 1 + (limits.arg_vector_terminator - limits.arg_vector_start),
		/* additional_argv_entries */ NULL,
		/* total_bytes_at_dest */ bytes,
		/* additional_asciiz_data */ new_ld_preload_env_string,
		1u + strlen(new_ld_preload_env_string) /* just one string */
	);
	if (status.last_component_copied != AUXV_ASCIIZ)
	{
		/* This indicates an error. */
		die("could not copy the auxv");
	}
	struct auxv_limits new_lims = get_auxv_limits(status.maybe_auxv);
	assert(new_lims.p_argcount == new_auxv_block);
	if (env_vector_idx_to_update != -1)
	{
		/* This means we didn't add a new env vector entry. So we must
		 * update the old one. Or rather its new copy.
		 * FIXME: this is a bit fragile. We assume our string has ended up
		 * immediately after the "old asciiz's worth" of bytes. */
		new_lims.env_vector_start[env_vector_idx_to_update] =
				&new_lims.asciiz_start[limits.asciiz_end - limits.asciiz_start];
	}
	fflush(stderr);
	print_auxv(stderr, status.maybe_auxv);
	assert(environ_getenv("LD_PRELOAD", (char**) new_lims.env_vector_start));
	assert(0 == strcmp(environ_getenv("LD_PRELOAD", (char**) new_lims.env_vector_start),
		new_ld_preload_env_string + sizeof "LD_PRELOAD=" - 1 ));
	free(new_ld_preload_env_string); // we allocated this only if creating a new LD_PRELOAD string
skip_rewrite_auxv:
	// now we have "new_auxv_block" on the malloc heap; XXX: use it!
// We can't do a single memcpy, combining with low-stack below, because
// (1) non-x86-64 platforms don't do this, and
// (2) the copy above also added to the asciiz, whereas the one below wants
//     not to move asciiz. So we are forced to do two copies.
// We are also forced to allocate *some* storage that we do not free here,
// because the asciiz has to live somewhere.

	/* For the lcall instrumentation, we need to have a low stack.
	 * Since we don't come back here, now is the time to create a new stack
	 * and call the entry point with it.
	 *
	 * HACK: pick a low 8MB, mprotect it writeable, zero it, set rsp, go!
	 * We have already mapped some memory there, but perhaps not RW.
	 */
#if defined(__x86_64__) /* FIXME: something randomised and less arbitrary, + track unused <2GB space */
#define LOW_STACK_TOP  0x71000000
#define LOW_STACK_SIZE    8388608
	mprotect((void*)(LOW_STACK_TOP - LOW_STACK_SIZE), LOW_STACK_SIZE, PROT_READ|PROT_WRITE);
	bzero((void*)(LOW_STACK_TOP - LOW_STACK_SIZE), LOW_STACK_SIZE);
	/* __real_enter will reset the stack pointer, so make sure we influence it. */
	extern ElfW(auxv_t) *p_auxv;
	extern void *sp_on_entry;
	assert((uintptr_t) sp_on_entry == (uintptr_t) limits.p_argcount);
	/* We need to memcpy the initial stack, otherwise ld.so won't be able to get
	 * its aux vector and whatnot. We copy from the *end* of the asciiz block. */
#define N_AUXV_ENTRIES (1 + (new_auxv_block ? (new_lims.aux_vector_terminator - status.maybe_auxv) \
			                : (limits.aux_vector_terminator   - p_auxv)))
#define N_ENV_ENTRIES (1 + (limits.env_vector_terminator - limits.env_vector_start) \
			+ ((new_auxv_block && env_vector_idx_to_update == -1) ? 1 : 0))
#define N_ARGV_ENTRIES (1 + (limits.arg_vector_terminator - limits.arg_vector_start))
	/* Need to preserve 16-byte alignment */
	size_t copy_len = //ROUND_UP_PTR(
		sizeof (intptr_t) /* <-- argc */ +
		sizeof (char*) * (N_ENV_ENTRIES) +
		sizeof (char*) * (N_ARGV_ENTRIES) +
		sizeof (ElfW(auxv_t)) * (N_AUXV_ENTRIES) +
		/*((uintptr_t) limits.asciiz_end - (uintptr_t) limits.asciiz_start)*/ 0 // <-- don't copy asciiz here
		/*, 16)*/;
	void *new_sp_on_entry =  ROUND_DOWN_PTR(LOW_STACK_TOP - copy_len, 16); // <-- we need to preserve 16-byte alignment of the stack
	//memcpy(new_sp_on_entry, sp_on_entry, memcpy_len);
	struct auxv_copy_status final_copy_status = copy_and_resize_auxv((char*) new_sp_on_entry,
		new_auxv_block ? status.maybe_auxv : p_auxv,
		new_auxv_block ? &new_lims : &limits,
		/* n entries incl terminator -- same */
		N_AUXV_ENTRIES,
		/* additional_auxv_entries   */ NULL,
		/* n_env_entries_incl_terminator */ N_ENV_ENTRIES,
		/* additional_env_entries */ NULL,
		/* n_argv_entries_incl_terminator */ N_ARGV_ENTRIES,
		/* additional_argv_entries */ NULL,
		/* total_bytes_at_dest */ copy_len,
		/* additional_asciiz_data */ NULL,
		0
	);
	assert(final_copy_status.last_component_copied == AUXV_AUX_VECTOR); // asciiz should stay where it was!
	debug_printf(0, "low stack: replacing rsp=%p with %p\n", sp_on_entry, new_sp_on_entry);
	sp_on_entry = new_sp_on_entry;
	/* XXX: how will the ld.so actually locate the auxv? I'm not sure we've done enough.
	 * Also the return value of AUXV_ENV_VECTOR, above, does not seem right. */
#endif
	/* FIXME: we never free this! The asciiz we need is contained within.
	 * Should we manage this another way? Probably, yes. */
	//if (new_auxv_block) free(new_auxv_block);
	// now we will proceed to the real entry point
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
