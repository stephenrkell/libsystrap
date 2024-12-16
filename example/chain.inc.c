/* We are a fragment of C code, called from a late pre-entry context in donald. */
// also snarf the shdrs (FIXME: we don't seem to use these anywhere? ah, trace-syscalls-ld does)
int inferior_fd = open(inferior_path, O_RDONLY); // HACK: re-open ld.so
off_t newloc = lseek(inferior_fd, inferior.ehdr.e_shoff, SEEK_SET);
ElfW(Shdr) shdrs[inferior.ehdr.e_shnum];
for (unsigned i = 0; i < inferior.ehdr.e_shnum; ++i)
{
	off_t off = inferior.ehdr.e_shoff + i * inferior.ehdr.e_shentsize;
	newloc = lseek(inferior_fd, off, SEEK_SET);
	if (newloc != off) die("could not seek to section header %d (0x%x) in %s (fd %d)\n", i, (unsigned) off, inferior_path, inferior_fd);
	size_t ntoread = MIN(sizeof shdrs[0], inferior.ehdr.e_shentsize);
	ssize_t nread = read(inferior_fd, &shdrs[i], ntoread);
	if (nread != ntoread) die("could not read section header %d in %s\n", i, inferior_path);
}
set_inferior_metadata(&inferior.ehdr, shdrs, (void*)inferior.phdrs_addr, inferior.base_addr, dt_debug);
create_fake_vdso(p_auxv);
close(inferior_fd);
