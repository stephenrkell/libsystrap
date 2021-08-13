void frob_dynamic(uintptr_t inferior_load_addr, uintptr_t inferior_dynamic_vaddr,
	ElfW(Phdr) *phdrs, unsigned phnum);
void set_inferior_metadata(ElfW(Ehdr) *ehdr, ElfW(Shdr) *shdrs, ElfW(Phdr) *phdrs, uintptr_t load_addr);
void create_fake_vdso(ElfW(auxv_t) *auxv);
