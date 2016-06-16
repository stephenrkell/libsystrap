#ifndef ELF_H_
#define ELF_H_

#include <unistd.h>
#include <elf.h>

#ifndef assert
#define elf_h_defined_assert
void __assert_fail(const char * assertion, const char * file, unsigned int line, const char * function);
#define assert(cond) if (!(cond)) __assert_fail(#cond, __FILE__, __LINE__, __func__)
#endif

/* relf needs assert() to be defined */
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

const void *vaddr_to_nearest_instruction(unsigned char *begin_addr, const char *fname, _Bool backwards, void **out_base_addr);

extern inline uintptr_t __attribute__((always_inline,gnu_inline))
page_boundary_up(uintptr_t addr)
{
	if (addr % PAGE_SIZE == 0) return addr;
	else return (PAGE_SIZE * (1 + (addr / PAGE_SIZE)));
}

extern inline uintptr_t __attribute__((always_inline,gnu_inline))
page_boundary_down(uintptr_t addr)
{
	return (addr / PAGE_SIZE) * PAGE_SIZE;
}

#ifdef elf_h_defined_assert
#undef assert
#endif

#endif
