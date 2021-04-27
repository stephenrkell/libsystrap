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
#include <xed/xed-interface.h>

extern _Bool xed_done_init;
static void copy_text_section(unsigned char *dest, const unsigned char *src, size_t sz,
	ElfW(Shdr) *the_shdr, ElfW(Shdr) *all_shdrs, unsigned shentsz)
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
						unsigned int memoplen = xed_decoded_inst_get_memory_operand_length(
							&xedd, 0);
						/*debug_printf(0*/ fprintf(stderr,
							"We saw an instruction at vdso vaddr %p with len %u displacement %lld memoplen %u\n",
							(inpos - src) + the_shdr->sh_addr, len, (long long) disp, memoplen);
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
}
static void copy_other_section(void *dest, void *src, size_t sz,
	ElfW(Shdr) *shdrs, unsigned shentsz)
{
	memcpy(dest, src, sz);
}
static void copy_and_trap_vdso_elf(void *dest, void *src, size_t sz)
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
				src_shdrs, src_ehdr->e_shentsize);
			trap_one_instruction_range(dest_addr, dest_addr + src_shdr->sh_size,
				1, 1);
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
	unsigned long max_off_seen = 0;
	ElfW(Ehdr) *src_ehdr = vdso_ehdr;

	for (unsigned i = 0; i < src_ehdr->e_shnum; ++i)
	{
		ElfW(Shdr) *shdr = (ElfW(Shdr) *) ((unsigned char *) src_ehdr + src_ehdr->e_shoff
			+ i * src_ehdr->e_shentsize);
		unsigned long endoff = shdr->sh_offset
			+ ((shdr->sh_type == SHT_NOBITS) ? 0 : shdr->sh_size);
		if (endoff > max_off_seen) max_off_seen = endoff;
	}
	ElfW(Phdr) *src_phdrs = (ElfW(Phdr) *) ((unsigned char *) vdso_ehdr + src_ehdr->e_phoff);
	for (unsigned i = 0; i < src_ehdr->e_phnum; ++i)
	{
		ElfW(Phdr) *phdr = (ElfW(Phdr) *) ((unsigned char *) src_phdrs + src_ehdr->e_phoff
			+ i * src_ehdr->e_phentsize);
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
				// make a temporary file
				char fname[] = "/tmp/tmp.XXXXXX";
				int fd = mkstemp(fname);
				if (fd == -1) abort();
				unlink(fname);
				mapping_sz = count_vdso_size((void*) p->a_un.a_val);
				int ret = ftruncate(fd, mapping_sz);
				if (ret == 0)
				{
					mapping = mmap(NULL, mapping_sz, PROT_READ|PROT_WRITE, MAP_SHARED,
						fd, 0);
					if (mapping != MAP_FAILED)
					{
						orig_vdso_ehdr_address = p->a_un.a_val;
						fake_vdso_ehdr_address = (uintptr_t) mapping;
					}
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
		copy_and_trap_vdso_elf(mapping, (void*) saw_at_sysinfo_ehdr_entry->a_un.a_val, mapping_sz);
		int ret __attribute__((unused)) = mprotect(mapping, mapping_sz, PROT_READ|PROT_EXEC);
		// swap in the fake vdso
		saw_at_sysinfo_ehdr_entry->a_un.a_val = (uintptr_t) mapping;
		assert(ret == 0);
	}
}
