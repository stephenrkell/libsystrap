/* chain.c -- should only contain functions specific to the
 * chain-loader (fake ld.so) that we use for init.*/

#define _GNU_SOURCE
#include <stdio.h>
#include <assert.h>

/* sys/types.h, but working around musl's paren-light style */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wparentheses"
#include <sys/types.h>
#pragma GCC diagnostic pop

#include <unistd.h>
#include <string.h> // for memcpy
#include "dso-meta.h" // includes link.h
#include "chain.h"
#include "donald.h"
#include "relf.h"
#include "systrap.h"

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

/* This gets called from the CHAIN_LOADER macro-inserted call in main.c...
 * see Makefile. */
void frob_dynamic(uintptr_t inferior_load_addr, uintptr_t inferior_dynamic_vaddr,
	ElfW(Phdr) *phdrs, unsigned phnum)
{
	/* We should have a spare entry in the _DYNAMIC section. 
	 * We use the space to insert our DT_DEBUG entry.
	 * First we want tocheck we really do have room to spare.
	 * PROBLEM: can't use _DYNAMIC because there is no way to
	 * --export-dynamic it. Instead we use PT_DYNAMIC. */
	ElfW(Phdr) *our_dynamic_phdr = NULL;
	for (unsigned i = 0; i < phnum; ++i)
	{
		if (phdrs[i].p_type == PT_DYNAMIC)
		{
			our_dynamic_phdr = &phdrs[i];
			break;
		}
	}

	if (our_dynamic_phdr)
	{
		unsigned dynamic_size = our_dynamic_phdr->p_memsz;
		unsigned dt_null_offset = 0;
		ElfW(Dyn) *d = &_DYNAMIC[0];
		for (;
				(uintptr_t) d - (uintptr_t) &_DYNAMIC[0] < dynamic_size
				&& d->d_tag != DT_NULL;
				++d, dt_null_offset += sizeof (ElfW(Dyn)));

		if ((intptr_t) d + sizeof (ElfW(Dyn)) - (intptr_t) &_DYNAMIC[0] <= dynamic_size)
		{
			// we have a dyn's worth of space, so frob it
			ElfW(Dyn) *ldso_d = (ElfW(Dyn) *)(inferior_load_addr + inferior_dynamic_vaddr);
			ElfW(Sym) *found_ldso_r_debug = symbol_lookup_in_dyn(ldso_d, inferior_load_addr, "_r_debug");
			if (found_ldso_r_debug)
			{
				struct r_debug *r = (struct r_debug *)(inferior_load_addr +
					found_ldso_r_debug->st_value);
				// make *our* _DYNAMIC point to the *inferior*'s _r_debug
				*d++ = (ElfW(Dyn)) { .d_tag = DT_DEBUG, .d_un = {
					/* First thought: let's use need the offset from *our*
					 * load address to the in-ld.so _r_debug, i.e.
					 *
					 * (1)  r-debug-ldso-addr - chain-loader-begin-addr
					 *
					 * .... a large-magnitude positive or negative number.
					 * When it gets ADJUST_DYN_INFO'd, it'll be
					 *
					 * (2)  r-debug-ldso-addr - chain-loader-begin-addr
					 *         + chain-loader-begin-addr
					 *
					 * i.e. exactly what we want.
					 *
					 * PROBLEM: we can't use (1) with RELF_MAYBE_ADJUST,
					 * because the large-magnitude number will be interpreted
					 * as not in need of relocation.
					 *
					 * We could hack RELF_MAYBE_ADJUST to narrow the "no
					 * relocation needed" window, so it's less likely to cover
					 * the large-magnitude number we end up with. How do we
					 * narrow it? We could only deem it already-relocated if
					 * it fits into a narrow [load-addr, limit-addr) range.
					 * That assumes we know the limit addr.
					 *
					 * Also, why does this work on 32-bit? Presumably, the
					 * large-magnitude number *is* interpreted as in need of
					 * relocation, because it happens to be less than the
					 * load address of the chain loader. Indeed it seems
					 * the chain loader gets an address in the f7a..... region,
					 * whereas the inferior is at 55556000. The subtraction
					 * gives roughly 0x5db56000, clearly less than f7a.....
					 *
					 * Here we are relying on a strange property: that
					 * when we add this value to our own load address,
					 * we get the structure within the inferior ld.so.
					 * PROBLEM: this will confuse RELF_MAYBE_ADJUST
					 * if it is a very high value (i.e. a negative offset),
					 * i.e. if we are loaded *higher* than the inferior.
					 * In turn, it means our own find_r_debug() logic,
					 * which uses RELF_MAYBE_ADJUST will omit to
					 * relocate it. So maybe... if the unsigned delta
					 * is bigger than our load address, don't relocate it?
					 * PROBLEM: what if it gets ADJUST_DYN_INFO'd? Seems not to.
					 * PROBLEM: this is still broken if we don't do the subtraction.
					 * RELF_MAYBE_ADJUST(this-value, chain-ld-so-load-address) is broken
					 * because if the inferior ld.so was loaded below us,
					 * it passes the 'should relocate' test, so gets a bogus
					 * offset added.
					 * It's also broken if we *do* do the subtraction, if the
					 * difference still looks like an address above our load address
					 * or (maybe) the ld.so's load address. That might happen if we
					 * are loaded low. */
					d_ptr: ((uintptr_t) r - (uintptr_t) &_begin)
				} };
				// fill in the inferior's _r_debug
				r->r_version = 0;
				r->r_map = &temporary_link_map;
				r->r_brk = (ElfW(Addr)) NULL;
				r->r_state = RT_CONSISTENT;
				/* The memory address at which the dynamic loader is loaded... hmm. Which one? */
				r->r_ldbase = inferior_load_addr;
				ElfW(Dyn) *found_debug = dynamic_xlookup(&_DYNAMIC[0], DT_DEBUG);
				assert(found_debug);
				*d = (ElfW(Dyn)) { .d_tag = DT_NULL, .d_un = { d_ptr: 0x0 } };
			}
		}
	}
}

void set_inferior_metadata(ElfW(Ehdr) *ehdr, ElfW(Shdr) *shdrs, ElfW(Phdr) *phdrs, uintptr_t load_addr)
{
	temporary_file_metadata.ehdr = ehdr;
	temporary_file_metadata.shdrs = shdrs;
	ElfW(Addr) max_vaddr = 0;
	for (unsigned i = 0; i < ehdr->e_phnum; ++i)
	{
		ElfW(Addr) max_vaddr_this_obj = phdrs[i].p_vaddr + phdrs[i].p_memsz;
		if (max_vaddr_this_obj > max_vaddr) max_vaddr = max_vaddr_this_obj;
	}
	temporary_link_map.l_addr = ldso_load_addr = load_addr;
	ldso_end_addr = ldso_load_addr + max_vaddr;
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
