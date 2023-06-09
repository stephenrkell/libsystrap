void set_inferior_metadata(ElfW(Ehdr) *ehdr, ElfW(Shdr) *shdrs, ElfW(Phdr) *phdrs, uintptr_t load_addr, ElfW(Dyn) *created_dt_debug);
void create_fake_vdso(ElfW(auxv_t) *auxv);
