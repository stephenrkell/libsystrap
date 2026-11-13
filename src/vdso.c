#define _GNU_SOURCE
#include <stdio.h>
#include <assert.h>
#include <stdlib.h> // for mkstemp
#include <sys/types.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h> // for memcpy
#include "vas.h"
#include "dso-meta.h"
#include "relf.h"
#include "systrap.h"
#define XED_ENCODER
#include <xed/xed-interface.h>

/* How do we handle the vDSO?
 *
 * On 32-bit x86, many syscalls are funnelled through a single 'sysenter'
 * or 'syscall' instruction, depending on microarch, within __kernel_vsyscall.
 *
 * To see those syscalls, we need to trap this.
 *
 * However, 
 * It is magic in the sense of mapping some kernel memory. So if we take
 * a copy, it will break the link.
 * On my system, the 32-bit vDSO right now (20250620) has phdrs like this:

Program Header:
    LOAD off 0x0000 vaddr 0x0000 align 2**12 filesz 0x128c memsz 0x128c flags r-x
 DYNAMIC off 0x031c vaddr 0x031c align 2**2  filesz 0x0090 memsz 0x0090 flags r--
    NOTE off 0x03b8 vaddr 0x03b8 align 2**2  filesz 0x0060 memsz 0x0060 flags r--
EH_FRAME off 0x0418 vaddr 0x0418 align 2**2  filesz 0x0024 memsz 0x0024 flags r--

 * ... i.e. the actual content fits in a single page. Our approach is to copy
 * the text to our new 'fake' vDSO but leave references to the *original* data.
 *
 * It is clear from a GitHub issue I raise when I first wrote this code...
 * https://github.com/stephenrkell/libsystrap/issues/15
 * ... that even then-me did not understand what it was doing. Certainly it did
 * let us trap the vDSO-using syscalls, which was good.
 *
 * Since global data references are not PC-relative on i386, my guess is that
 * the kernel text is pre-relocated for the chosen vDSO load address. In that case,
 * the instructions are PC-relative and therefore relocatable, but will naturally
 * referencing the original data. I suspect that is why it works.
 *
 * As a preload library we have particular problems because the dynamic linker
 * has already bound to the real vDSO.
 * XXX: can we just insert a trap in the real vDSO? No, it's not writable.
 * XXX: can we just map a trap-modified page on top of the real vDSO? Maybe, but
 * that will break the magic link to the magic data.
 * XXX: can we redirect references? If we are an audit library, yes. Otherwse... hmm?
 *
 * TODO: get a look at the code that links to the vDSO? It does not seem
 * to be normal linkage, because none of the UND symbols in libc.so.6 are ones
 * that the vDSO defines.
 */

extern _Bool xed_done_init;
static void copy_text_section(unsigned char *dest, const unsigned char *src, size_t sz,
	ElfW(Shdr) *the_shdr, ElfW(Shdr) *all_shdrs, unsigned shentsz,
	ElfW(Addr) min_vaddr, ElfW(Addr) max_vaddr)
{
	/* We walk the instructions one at a time. Any that has a
	 * memory operand outside the text section is considered
	 * for rewriting. */
	const unsigned char *inpos = src;
	unsigned char *outpos = dest;
	const unsigned char *end = inpos + sz;
	if (!xed_done_init)
	{
		xed_tables_init();
		xed_done_init = 1;
	}
	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero(&xedd);
	fprintf(stderr,
		"Decoding %u bytes from vaddr %p\n", (unsigned) sz, (void*) the_shdr->sh_addr);
	unsigned len = 0;
	while (inpos < end)
	{
		// debugging
#if 0
		if (end - inpos >= 5)
		{
			fprintf(stderr, "At %04p, next five bytes are: %02x %02x %02x %02x %02x\n",
				the_shdr->sh_addr + (inpos - src),
				(int) inpos[0], (int) inpos[1], (int) inpos[2], (int) inpos[3], (int) inpos[4]);
		}
#endif
		xed_decoded_inst_zero(&xedd);
		xed_decoded_inst_set_mode(&xedd,
#if defined(__x86_64__)
			XED_MACHINE_MODE_LONG_64,
			XED_ADDRESS_WIDTH_64b
#elif defined(__i386__)
			XED_MACHINE_MODE_LEGACY_32,
			XED_ADDRESS_WIDTH_32b
#else
#error "Unrecognised x86 architecture."
#endif
		);

		xed_error_enum_t xed_error = xed_decode(&xedd, inpos, end - inpos);
		if (xed_error == XED_ERROR_NONE)
		{
			len = xed_decoded_inst_get_length(&xedd);
#if 0
			fprintf(stderr,
				"Decoded instruction at vdso vaddr %p with len %u\n",
				(inpos - src) + the_shdr->sh_addr, len);
#endif
			switch (xed_decoded_inst_number_of_memory_operands(&xedd))
			{
				case 0: goto copy_verbatim;
				case 1: {
					/* How does the x86 vDSO address the magic memory locations
					 * for gettimeofday() etc.? */
					
					
					// what is the displacement relative to? we care about PC-relative only
					xed_reg_enum_t base_reg = xed_decoded_inst_get_base_reg(
						&xedd, /* mem_idx */ 0);
					if (base_reg == XED_REG_RIP || base_reg == XED_REG_EIP)
					{
						xed_int64_t disp = xed_decoded_inst_get_memory_displacement(
							&xedd, /* mem_idx */ 0);
						unsigned int memdispw = xed_decoded_inst_get_memory_displacement_width(
							&xedd, 0);
						/* Does this displacement land us within the object, or outside it? */
						intptr_t starting_vaddr = the_shdr->sh_addr + (inpos + len - src);
						intptr_t target_vaddr = starting_vaddr + disp;
						_Bool outside = target_vaddr < min_vaddr || target_vaddr >= max_vaddr;
						/*debug_printf(0*/ fprintf(stderr,
							"We saw an instruction at vdso vaddr %p with len %u displacement %lld memdispw %u tgt %lx; we think it lands %s vDSO\n",
							(inpos - src) + the_shdr->sh_addr, len, (long long) disp, memdispw, target_vaddr,
							outside ? "outside" : "inside"
							);
						if (outside)
						{
							/* We need to re-encode the instruction. Can xed do this for us?
							 * Yes. The encoder request type is a typedef of the decoded inst type,
							 * so we can go straight from decode to re-encode with changes. */
							xed_int64_t new_disp = disp + (src - dest);
							xed_encoder_request_init_from_decode(&xedd);
							xed_encoder_request_set_memory_displacement(&xedd, new_disp, memdispw);
							unsigned encoded_len = 0;
							xed_error_enum_t err = xed_encode(&xedd, (xed_uint8_t*) outpos, end - outpos,
								&encoded_len);
							if (err == XED_ERROR_NONE)
							{
								assert(encoded_len == len);
								fprintf(stderr, "Successfully re-encoded with new displacement %lx\n",
									(long) new_disp);
								inpos += len;
								outpos += encoded_len;
								continue;
							}
							// else fall through to copying verbatim
							fprintf(stderr, "Failed to encode with new displacement %lx (error %d), so falling through\n",
								(long) new_disp, (int) err);
						}
					}
					goto copy_verbatim; // FIXME
				} break;
				case 2:
					/*debug_printf(0,*/
					fprintf(stderr, "Skipping vDSO instruction with >1 memory operand\n");
					// fall through
				default:
				copy_verbatim:
					memcpy(outpos, inpos, len);
					inpos += len;
					outpos += len;
			}
		}
		else
		{
			// HMM. We couldn't decode. What to do? Copy one byte and carry on
			fprintf(stderr, "Decode failed at %p, so advancing one byte\n",
				(inpos - src) + the_shdr->sh_addr);
			if (end - inpos >= 5)
			{
				fprintf(stderr, "At failure vaddr %04p, previous len was %u, next five bytes were: %02x %02x %02x %02x %02x\n",
					the_shdr->sh_addr + (inpos - src), len,
					(int) inpos[0], (int) inpos[1], (int) inpos[2], (int) inpos[3], (int) inpos[4]);
			}
			*outpos++ = *inpos++;
		}
	}

}
static void copy_data_section(void *dest, void *src, size_t sz,
	ElfW(Shdr) *shdrs, unsigned shentsz)
{
	/* Generally we want to keep using the kernel's data, so
	 * we don't need to copy anything. However, the vDSO typically
	 * uses a single LOAD for both text and rodata (there may be
	 * no writable data), so this might be tricky. */

	// XXX: we copy the section. This does not prevent text from
	// referencing the *old*(real) vDSO's data/rodata sections.
	memcpy(dest, src, sz);
}
static void copy_other_section(void *dest, void *src, size_t sz,
	ElfW(Shdr) *shdrs, unsigned shentsz)
{
	memcpy(dest, src, sz);
}
static void copy_and_trap_vdso_elf(void *dest, void *src, size_t sz,
	ElfW(Addr) min_vaddr, ElfW(Addr) max_vaddr)
{
	/* In an ELF, everything is either an ELF header,
	 * program header, section header or section. */
	ElfW(Ehdr) *src_ehdr = src;
	memcpy(dest, src_ehdr, sizeof (ElfW(Ehdr)));
	ElfW(Shdr) *src_shdrs = (ElfW(Shdr) *) ((unsigned char *) src + src_ehdr->e_shoff);
	for (unsigned i = 0; i < src_ehdr->e_shnum; ++i)
	{
		ElfW(Shdr) *src_shdr = (ElfW(Shdr) *)((unsigned char *) src_shdrs + i * src_ehdr->e_shentsize);
		ElfW(Shdr) *dest_shdr = (ElfW(Shdr) *)((unsigned char *) dest + src_ehdr->e_shoff
			+ i * src_ehdr->e_shentsize);
		memcpy(dest_shdr, src_shdr, src_ehdr->e_shentsize);
		unsigned char *dest_addr = (unsigned char *) dest + src_shdr->sh_offset;
		unsigned char *src_addr = (unsigned char *) src + src_shdr->sh_offset; 
		if (src_shdr->sh_flags & SHF_EXECINSTR)
		{
			copy_text_section(dest_addr, src_addr, src_shdr->sh_size, src_shdr,
				src_shdrs, src_ehdr->e_shentsize, min_vaddr, max_vaddr);
			trap_one_instruction_range(dest_addr, dest_addr + src_shdr->sh_size,
				1, 1, 0, set_default_trap, NULL);
		}
		else if (src_shdr->sh_flags & SHF_ALLOC && src_shdr->sh_type != SHT_NOBITS)
		{
			copy_data_section(dest_addr, src_addr, src_shdr->sh_size,
				src_shdrs, src_ehdr->e_shentsize);
		}
		else copy_other_section(dest_addr, src_addr, src_shdr->sh_size,
				src_shdrs, src_ehdr->e_shentsize);
	}
	ElfW(Phdr) *src_phdrs = (ElfW(Phdr) *) ((unsigned char *) src + src_ehdr->e_phoff);
	for (unsigned i = 0; i < src_ehdr->e_phnum; ++i)
	{
		ElfW(Phdr) *src_phdr = (ElfW(Phdr) *)((unsigned char *) src_phdrs + i * src_ehdr->e_phentsize);
		ElfW(Phdr) *dest_phdr = (ElfW(Phdr) *)((unsigned char *) dest + src_ehdr->e_phoff
			+ i * src_ehdr->e_phentsize);
		memcpy(dest_phdr, src_phdr, src_ehdr->e_phentsize);
		// HM. We copied them verbatim. Is that what we wanted? Yes, probably.
	}
}

static
size_t
count_vdso_size(void *vdso_ehdr)
{
	ElfW(Ehdr) *ehdr = vdso_ehdr;
	/* Usually the section headers are the last thing in the file. */
	unsigned long max_off_seen = ehdr->e_shoff + ehdr->e_shnum * ehdr->e_shentsize;
	/* ... but it's possible for the program headers to go anywhere. */
	unsigned long ph_endoff = ehdr->e_phoff + ehdr->e_phnum * ehdr->e_phentsize;
	if (ph_endoff > max_off_seen) max_off_seen = ph_endoff;

	/* Same idea for all sections... */
	for (unsigned i = 0; i < ehdr->e_shnum; ++i)
	{
		ElfW(Shdr) *shdr = (ElfW(Shdr) *) ((unsigned char *) ehdr + ehdr->e_shoff
			+ i * ehdr->e_shentsize);
		unsigned long endoff = shdr->sh_offset
			+ ((shdr->sh_type == SHT_NOBITS) ? 0 : shdr->sh_size);
		if (endoff > max_off_seen) max_off_seen = endoff;
	}
	/* ... and for all phdrs. FIXME: should limit this to some phdr types only I think. */
	for (unsigned i = 0; i < ehdr->e_phnum; ++i)
	{
		ElfW(Phdr) *phdr = (ElfW(Phdr) *) ((unsigned char *) ehdr + ehdr->e_phoff
			+ i * ehdr->e_phentsize);
		unsigned long endoff = phdr->p_offset + phdr->p_filesz;
		if (endoff > max_off_seen) max_off_seen = endoff;
	}
	return ROUND_UP(max_off_seen, COMMON_PAGE_SIZE /* FIXME: ??? */);
}

void create_fake_vdso(ElfW(auxv_t) *auxv)
{
	/* Firstly, find the original vdso. */
	ElfW(auxv_t) *saw_at_sysinfo_entry = NULL;
	ElfW(auxv_t) *saw_at_sysinfo_ehdr_entry = NULL;
	uintptr_t orig_vdso_ehdr_address = 0;
	uintptr_t fake_vdso_ehdr_address = 0;
	void *mapping = MAP_FAILED;
	size_t mapping_sz;
	for (ElfW(auxv_t) *p = auxv; p->a_type; ++p)
	{
		switch (p->a_type)
		{
			case AT_SYSINFO:
				/* This is the vsyscall entry point. It is deprecated. */
				saw_at_sysinfo_entry = p;
				break;
			case AT_SYSINFO_EHDR: {
				saw_at_sysinfo_ehdr_entry = p;
				mapping_sz = count_vdso_size((void*) p->a_un.a_val);
#define HAVE_MEMFD_CREATE 1 /* FIXME: configure-time check */
#if HAVE_MEMFD_CREATE
				int fd = memfd_create("fake-vdso", MFD_CLOEXEC);
				if (fd == -1) abort();
#else
				// make a temporary file
				char fname[] = "/tmp/tmp.XXXXXX";
				int fd = mkstemp(fname);
				if (fd == -1) abort();
				unlink(fname);
#endif
				int ret = ftruncate(fd, mapping_sz);
				if (ret == 0)
				{
					/* HACK: need to constrain the mapping s.t. it is close to the real vDSO.
					 * FIXME: could we map over the real vDSO? check whether Linux permits this. */
#define MAX_ATTEMPTS 128
					for (unsigned i = 0; i < MAX_ATTEMPTS; ++i)
					{
						mapping = mmap(
							(void*)((uintptr_t) p->a_un.a_val + (2+i) * MIN_PAGE_SIZE),
							mapping_sz, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED_NOREPLACE,
							fd, 0);
						if (mapping != MAP_FAILED) break;
						/* Alternate going backwards in MIN_HUGEPAGE_SIZE units */
						mapping = mmap(
							(void*)((uintptr_t) p->a_un.a_val - (2+i) * MIN_HUGEPAGE_SIZE),
							mapping_sz, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED_NOREPLACE,
							fd, 0);
						if (mapping != MAP_FAILED) break;
					}
					if (mapping != MAP_FAILED)
					{
						orig_vdso_ehdr_address = p->a_un.a_val;
						fake_vdso_ehdr_address = (uintptr_t) mapping;
					}
					else abort();
				}
				close(fd);
			} break;
			default:
				continue;
		}
	}
	/* We need to set up real_sysinfo and fake_sysinfo before we
	 * do the copy_and_trap_vdso_elf, because we need to snarf
	 * the magic "landing pad" offset within the vsyscall while
	 * we do the trapping.  */
	if (saw_at_sysinfo_entry)
	{
		assert(saw_at_sysinfo_ehdr_entry);
		real_sysinfo = (void*) saw_at_sysinfo_entry->a_un.a_val;
		fake_sysinfo = (void*) (fake_vdso_ehdr_address
			+ ((uintptr_t) real_sysinfo - orig_vdso_ehdr_address));
		saw_at_sysinfo_entry->a_un.a_val = (uintptr_t) fake_sysinfo;
	}
	if (mapping != MAP_FAILED)
	{
		assert(saw_at_sysinfo_ehdr_entry);
		/* Let's walk the headers of the ELF file, to help us create our fake one. */
		/* 1. Get the minimum and maximum vaddr from the PT_LOAD headers.
		 *    This will help us tell apart internal from external PC-relative references.
		 * 2. If we didn't see AT_SYSINFO, we won't have a fake_sysinfo value; use the vdso's
		 *    symtab to calculate its value, for uniformity. FIXME: I think we'll never use it,
		 *    because lack of AT_SYSINFO implies x86_64, whereas AT_SYSINFO and the TLS-based
		 *    32-bit via-VDSO syscall/sysenter pathway are only used on i386. */
		ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *) orig_vdso_ehdr_address;
		uintptr_t orig_load_addr = orig_vdso_ehdr_address;
		uintptr_t fake_load_addr = (uintptr_t) mapping;
		ElfW(Addr) min_vaddr_seen = (ElfW(Addr)) -1;
		ElfW(Addr) max_vaddr_seen = 0;
		for (ElfW(Phdr) *phdr0 = (ElfW(Phdr) *)((char*) ehdr + ehdr->e_phoff),
		                *phdr = phdr0;
		     phdr != phdr0 + ehdr->e_phnum;
		     phdr = (ElfW(Phdr) *)(((char*) phdr) + ehdr->e_phentsize))
		{
			if (phdr->p_type == PT_LOAD)
			{
				ElfW(Addr) low = phdr->p_vaddr;
				ElfW(Addr) high = phdr->p_vaddr + phdr->p_memsz;
				if (low < min_vaddr_seen) min_vaddr_seen = low;
				if (high > max_vaddr_seen) max_vaddr_seen = high;
			}
			if (phdr->p_type == PT_DYNAMIC)
			{
				ElfW(Dyn) *d = (ElfW(Dyn) *)(orig_load_addr + phdr->p_vaddr);
				/* Did we get a good dyn? Sanity check by counting its entries. */
				unsigned n = 0;
				for (ElfW(Dyn) *i = d; i->d_tag != DT_NULL; ++i, ++n);
				assert(n > 0);
				assert(n < phdr->p_memsz / sizeof (ElfW(Dyn)));
				assert(n >= 0.5 * phdr->p_memsz / sizeof (ElfW(Dyn)));
				/* OK, seems sane. */
				ElfW(Sym) *symtab = get_dynsym_from_dyn(d, orig_load_addr);
				unsigned char *strtab = get_dynstr_from_dyn(d, orig_load_addr);
				ElfW(Word) *sysv_hash = get_sysv_hash_from_dyn(d, orig_load_addr);
				ElfW(Word) *gnu_hash = get_gnu_hash_from_dyn(d, orig_load_addr);
				ElfW(Sym) *vsyscall_sym = NULL;
				if (gnu_hash) vsyscall_sym = gnu_hash_lookup(gnu_hash, symtab, strtab,
						"__kernel_vsyscall");
				else if (sysv_hash) vsyscall_sym = hash_lookup(sysv_hash, symtab, strtab,
						"__kernel_vsyscall");
				// use the new fake load addr to resolve the symbol in the fake space
				if (vsyscall_sym) fake_sysinfo = sym_to_addr_given_base(fake_load_addr,
						vsyscall_sym);
			}
		}

		copy_and_trap_vdso_elf(mapping, (void*) saw_at_sysinfo_ehdr_entry->a_un.a_val, mapping_sz,
			min_vaddr_seen, max_vaddr_seen);
		int ret __attribute__((unused)) = mprotect(mapping, mapping_sz, PROT_READ|PROT_EXEC);
		// swap in the fake vdso
		saw_at_sysinfo_ehdr_entry->a_un.a_val = (uintptr_t) mapping;
		assert(ret == 0);
	}
}
