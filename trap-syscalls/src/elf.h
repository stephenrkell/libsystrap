#ifndef ELF_H_
#define ELF_H_

#include <unistd.h>
#include <elf.h> /* for r_debug mischief */

#ifndef ElfW
#define ElfW(t) Elf64_ ## t
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

extern ElfW(Dyn) _DYNAMIC[];
extern struct r_debug _r_debug; /* defined by ld.so -- HMM, not portable really */
extern uintptr_t our_load_address;

// another non-portable thingy...
struct dl_phdr_info 
{
	ElfW(Addr) dlpi_addr;
	const char *dlpi_name;
	const ElfW(Phdr) *dlpi_phdr;
	ElfW(Half) dlpi_phnum;
};
int dl_iterate_phdr(
                 int (*callback) (struct dl_phdr_info *info,
                                  size_t size, void *data),
                 void *data);

void *hash_lookup(const char *sym) __attribute__((visibility("protected")));

const ElfW(Phdr) *vaddr_to_load_phdr(unsigned char *begin_addr, const char *fname, void **out_base_addr)
		__attribute__((visibility("protected")));

const void *vaddr_to_next_instruction_start(unsigned char *begin_addr, const char *fname, void **out_base_addr);

inline uintptr_t __attribute__((visibility("protected"))) 
page_boundary_up(uintptr_t addr)
{
	if (addr % PAGE_SIZE == 0) return addr;
	else return (PAGE_SIZE * (1 + (addr / PAGE_SIZE)));
}

inline uintptr_t __attribute__((visibility("protected")))
page_boundary_down(uintptr_t addr)
{
	return (addr / PAGE_SIZE) * PAGE_SIZE;
}

#endif
