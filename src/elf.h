#ifndef ELF_H_
#define ELF_H_

#include <unistd.h>
#include <elf.h>
#include <relf.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

extern uintptr_t our_load_address;

// another non-portable thingy... FIXME: replace dl_iterate_phdr with 
// walking the link_map, *or* implement our own dl_iterate_phdr for portability
struct dl_phdr_info 
{
	ElfW(Addr) dlpi_addr;
	const char *dlpi_name;
	const ElfW(Phdr) *dlpi_phdr;
	ElfW(Half) dlpi_phnum;
};

typedef int dl_cb_fn(struct dl_phdr_info *info, size_t size, void *data);
int dl_iterate_phdr(dl_cb_fn *callback, void *data);

const ElfW(Phdr) *vaddr_to_load_phdr(unsigned char *begin_addr, const char *fname, void **out_base_addr)
		__attribute__((visibility("protected")));
const ElfW(Ehdr) *vaddr_to_ehdr(unsigned char *begin_addr, const char *fname, void **out_base_addr)
		__attribute__((visibility("protected")));

const void *vaddr_to_next_instruction_start(unsigned char *begin_addr, const char *fname, void **out_base_addr);

				 uintptr_t __attribute__((visibility("protected"))) page_boundary_up(uintptr_t addr);
				 uintptr_t __attribute__((visibility("protected"))) page_boundary_down(uintptr_t addr);

#endif
