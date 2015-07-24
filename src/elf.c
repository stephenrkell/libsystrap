#include "elf.h"
#include <stddef.h>
#include <string.h>
#include <asm/fcntl.h>
#include <sys/mman.h>

#include <relf.h>

#include "do-syscall.h"
#include "raw-syscalls.h"

uintptr_t our_load_address __attribute__((visibility("protected")));

uintptr_t __attribute__((visibility("protected"))) 
page_boundary_up(uintptr_t addr)
{
	if (addr % PAGE_SIZE == 0) return addr;
	else return (PAGE_SIZE * (1 + (addr / PAGE_SIZE)));
}

uintptr_t __attribute__((visibility("protected")))
page_boundary_down(uintptr_t addr)
{
	return (addr / PAGE_SIZE) * PAGE_SIZE;
}



struct dl_fileoff_cb_arg
{
	unsigned char *addr_in_file;
	unsigned long fileoff;
	unsigned long filesz_min;
	struct dl_phdr_info *info_out;
	const void *vaddr_out;
};
static int dl_fileoff_cb(struct dl_phdr_info *info, size_t size, void *dummy_arg)
{
	struct dl_fileoff_cb_arg *arg = dummy_arg;
	
	/* Is this the file we're looking for? */
	_Bool is_the_file = 0;
	for (unsigned i = 0; i < info->dlpi_phnum; ++i)
	{
		const ElfW(Phdr) *p = &info->dlpi_phdr[i];
		
		unsigned char *phdr_begin_addr = (unsigned char *) info->dlpi_addr + p->p_vaddr;
		unsigned char *phdr_end_addr = phdr_begin_addr + p->p_memsz;
		if (phdr_begin_addr <= arg->addr_in_file 
				&& phdr_end_addr > arg->addr_in_file)
		{
			is_the_file = 1;
			break;
		}
	}
	
	if (is_the_file)
	{
		arg->info_out = info;
		/* walk the phdrs again, looking for a LOAD including our file offset */
		for (unsigned i = 0; i < info->dlpi_phnum; ++i)
		{
			const ElfW(Phdr) *p = &info->dlpi_phdr[i];
			if (p->p_type == PT_LOAD 
					&& page_boundary_down(p->p_offset) <= page_boundary_down(arg->fileoff)
					&& page_boundary_up(p->p_offset + p->p_filesz) > 
						page_boundary_up(arg->fileoff + arg->filesz_min))
			{
				arg->vaddr_out = (unsigned char *) info->dlpi_addr + p->p_vaddr + 
					(arg->fileoff - p->p_offset);
				return 1; /* stop now */
			}
		}
		
		/* can stop if we didn't find a mapping */
		return 1;
	}
	return 0; /* keep going */
}

struct dl_load_phdr_cb_arg
{
	unsigned char *begin_addr_in;
	struct dl_phdr_info *info_out;
	const ElfW(Phdr) *phdr_out;
};
static int dl_load_phdr_cb(struct dl_phdr_info *info, size_t size, void *dummy_arg)
{
	struct dl_load_phdr_cb_arg *arg = dummy_arg;
	
	for (unsigned i = 0; i < info->dlpi_phnum; ++i)
	{
		const ElfW(Phdr) *p = &info->dlpi_phdr[i];
		
		unsigned char *phdr_begin_addr = (unsigned char *) info->dlpi_addr + p->p_vaddr;
		unsigned char *phdr_end_addr = phdr_begin_addr + p->p_memsz;
		if (p->p_type == PT_LOAD
				&& phdr_begin_addr <= arg->begin_addr_in 
				&& phdr_end_addr > arg->begin_addr_in)
		{
			arg->phdr_out = p;
			arg->info_out = info;
			return 1; /* stop now */
		}
	}
	return 0; /* keep going */
}

const void *fileoff_to_vaddr(unsigned char *addr_in_file, unsigned long offset, unsigned long filesz_min)
{
	struct dl_fileoff_cb_arg arg = { addr_in_file, offset, filesz_min, NULL };
	int ret = dl_iterate_phdr(dl_fileoff_cb, &arg);
	if (ret)
	{
		assert(arg.info_out);
		return arg.vaddr_out; /* might be 0 */
	}
	return NULL;
}

const ElfW(Phdr) *vaddr_to_load_phdr(unsigned char *begin_addr, const char *fname, void **out_base_addr)
{
	struct dl_load_phdr_cb_arg arg = { begin_addr, NULL };
	int ret = dl_iterate_phdr(dl_load_phdr_cb, &arg);
	if (ret)
	{
		assert(arg.phdr_out);
		assert(arg.info_out);
		*out_base_addr = (void*) arg.info_out->dlpi_addr;
		return arg.phdr_out;
	}
	return NULL;
}

ElfW(Dyn) *dyn_lookup(ElfW(Dyn) *p_dyn, ElfW(Sword) tag)
{
	for (ElfW(Sword) i = 0; p_dyn[i].d_tag != DT_NULL; ++i)
	{
		if (p_dyn[i].d_tag == tag) return p_dyn;
	}
	return NULL;
}

const ElfW(Ehdr) *vaddr_to_ehdr(unsigned char *begin_addr, const char *fname, void **out_base_addr)
{
	return (const ElfW(Ehdr) *) fileoff_to_vaddr(begin_addr, 0, sizeof (ElfW(Ehdr)));
}

const void *vaddr_to_next_instruction_start(unsigned char *begin_addr, const char *fname, void **out_base_addr)
{
	void *base_addr = NULL;
	const ElfW(Ehdr) *ehdr = vaddr_to_ehdr(begin_addr, fname, &base_addr);
	if (ehdr)
	{
		if (out_base_addr) *out_base_addr = base_addr;
		// is the SHT mapped?
		const ElfW(Shdr) *sht = fileoff_to_vaddr(begin_addr, ehdr->e_shoff, ehdr->e_shnum * ehdr->e_shentsize);
		void *m = NULL;
		uintptr_t off_start = page_boundary_down(ehdr->e_shoff);
		uintptr_t off_end = page_boundary_up(ehdr->e_shoff + ehdr->e_shnum * ehdr->e_shentsize);
		if (!sht)
		{
			int fd = raw_open(fname, O_RDONLY);
			assert(fd >= 0);
			void *m = raw_mmap(NULL, off_end - off_start, PROT_READ, MAP_PRIVATE, fd, page_boundary_down(ehdr->e_shoff));
			assert(m != MAP_FAILED);
			sht = (ElfW(Shdr) *)((unsigned char *) m + (ehdr->e_shoff - page_boundary_down(ehdr->e_shoff)));
		}
		assert(sht);
		/* walk the SHT, looking for lower vaddr higher than begin_addr */
		uintptr_t current_lowest = (uintptr_t) -1;
		int current_lowest_i = -1;
		for (int i = 0; i < ehdr->e_shnum; ++i)
		{
			uintptr_t actual_section_vaddr
			 = (uintptr_t)(((unsigned char *) base_addr) + sht[i].sh_addr);
			if ((sht[i].sh_flags & SHF_EXECINSTR)
				&& (sht[i].sh_flags & SHF_ALLOC)
				&& actual_section_vaddr >= (uintptr_t) begin_addr 
				&& actual_section_vaddr < current_lowest)
			{
				current_lowest_i = i;
				current_lowest = actual_section_vaddr;
			}
		}

		if (current_lowest_i != -1)
		{
			return (void*) current_lowest;
		}
		// else fall through

		if (m) raw_munmap(m, off_end - off_start);
	}
	
	return NULL;
}
