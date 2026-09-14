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
#include <unistd.h>
#include <string.h> // for memcpy
#include "dso-meta.h" // includes link.h
#include "donald.h"
#include "chain.h"    // from donald
#include "chain-decls.h"  // ours (FIXME: rename chain-ext.h)
#include "relf.h"
#include "systrap.h"
#include "trace-syscalls.h"

extern uintptr_t __start___replaced_syscalls[];
extern uintptr_t __stop___replaced_syscalls[];

extern void __attribute__((visibility("protected")))
(*__systrap_post_handling)(struct generic_syscall *gsp, long int ret);
extern void __attribute__((visibility("protected")))
(*__systrap_pre_handling)(struct generic_syscall *gsp);

void __attribute__((visibility("protected")))
__trace_syscalls_pre_handling(struct generic_syscall *gsp);
void __attribute__((visibility("protected")))
__trace_syscalls_post_handling(struct generic_syscall *gsp, long ret);

static struct link_map temporary_link_map = {
	.l_name = "",
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

	// phdrs; /* always mapped or copied by ld.so */
	// phnum;
	// nload; /* number of segments that are LOADs */
	// vaddr_begin; /* the lowest mapped vaddr in the object */
	// vaddr_end; /* one past the last mapped vaddr in the object */

	.dynsym = NULL,/* always mapped by ld.so */
	.dynstr = NULL, /* always mapped by ld.so */
	.dynstr_end = NULL,

	.dynsymndx = 0, // section header idx of dynsym, or 0 if none such
	.dynstrndx = 0 //,

	//.extra_mappings = {
	//	(struct extra_mapping) { .mapping_pagealigned = , .fileoff_pagealigned = , .size =  }
	//},

	// .ehdr = ,
	// .shdrs = //,
	// shstrtab;
	// symtab; // NOTE this really is symtab, not dynsym
	// symtabndx;
	// strtab; // NOTE this is strtab, not dynstr
	// strtabndx;
	
	//.segments = { (struct segment_metadata) { } }
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
static void set_temporary_link_map(ElfW(Ehdr) *ehdr, ElfW(Shdr) *shdrs, ElfW(Phdr) *phdrs,
	uintptr_t inferior_load_addr, ElfW(Dyn) *created_dt_debug)
{
	if (!created_dt_debug) return;
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
	struct r_debug *r = (struct r_debug *) created_dt_debug->d_un.d_ptr;
	assert(r);
	r->r_version = 0;
	r->r_map = 0;
	r->r_brk = (ElfW(Addr)) NULL;
	r->r_state = 0 /*RT_CONSISTENT*/;
	r->r_ldbase = 0;
}

struct file_metadata *__wrap___runt_files_metadata_by_addr(void *addr)
{
	if ((uintptr_t) addr >= ldso_load_addr
		 && (uintptr_t) addr < ldso_end_addr)
	{
		return &temporary_file_metadata;
	}
	return NULL;
}

// we have another special way to die
#define die(s, ...) do { debug_printf(0, s , ##__VA_ARGS__); abort(); } while(0)

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

	// FIXME: libsystrap isn't being init'd, so force it
	__libsystrap_force_init();
	/* Install replacements. Recall that these are used for bootstrapping,
	 * since unlike the preload library case, most text is not loaded yet.
	 *
	 * Why not just initialize the replaced_syscalls array itself?
	 * Well, it can't be split across multiple files, unlike this approach.
	 * This is a bit nasty though.
	 */
	unsigned nreplacements = (__stop___replaced_syscalls - __start___replaced_syscalls) / 2;
	for (unsigned n = 0; n < nreplacements; ++n)
	{
		uintptr_t syscall_n = __start___replaced_syscalls[2*n];
		assert(syscall_n < SYSCALL_MAX);
		void (*replacement)(struct generic_syscall *s/*, post_handler *post*/)
		 = (void*)__start___replaced_syscalls[2*n + 1];
		replaced_syscalls[syscall_n] = replacement;
	}

	start_tracing(p_auxv);

	// this is undoing the effect of set_temporary_link_map
	clear_temporary_link_map(cc->our_dt_debug);
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
