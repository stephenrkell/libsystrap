/*
 * Implementations of various substitution functions and helper functions
 * called during syscall emulation.
 */

#include "do-syscall.h"
#include "syscall-names.h"
#include <uniqtype.h> /* from liballocs; for walking footprints */
#include <elf.h> /* for r_debug mischief */
#include <string.h>

#ifndef ElfW
#define ElfW(t) Elf64_ ## t
#endif

extern ElfW(Dyn) _DYNAMIC[];
static ElfW(Word) *hash;
static ElfW(Sym) *symtab;
static const char *strtab;
uintptr_t our_load_address __attribute__((visibility("protected")));

/* explicitly declare the dlsym interface, to avoid libc headers. */

#define REPLACE_ARGN(n_arg, count)				      \
	long int arg ## n_arg = gsp->arg ## n_arg ;		     \
	gsp->arg ## n_arg =					     \
		(long int) lock_memory(arg ## n_arg , (count), 0);

#define RESTORE_ARGN(n_arg, count)				      \
	free_memory(gsp->arg ## n_arg, arg ## n_arg, (count));	  \
	gsp->arg ## n_arg = arg ## n_arg;

static void init_hash(void)
{
	/* Find the hash table. We run too early to call dynamic loader functions
	 * (which might make syscalls, anyway, which would not be good). */
	for (ElfW(Dyn) *dyn = _DYNAMIC; dyn->d_tag != DT_NULL; ++dyn)
	{
		if (dyn->d_tag == DT_HASH)
		{
			hash = (void*) dyn->d_un.d_ptr;
		}
		if (dyn->d_tag == DT_SYMTAB)
		{
			symtab = (void*) dyn->d_un.d_ptr;
		}
		if (dyn->d_tag == DT_STRTAB)
		{
			strtab = (void*) dyn->d_un.d_ptr;
		}
	}
	assert(symtab);
	assert(strtab);
}

static unsigned long
elf64_hash(const unsigned char *name)
{
	unsigned long h = 0, g;
	while (*name)
	{
		h = (h << 4) + *name++;
		if (0 != (g = (h & 0xf0000000))) h ^= g >> 24;
		h &= 0x0fffffff;
	}
	return h;
}

static void *hash_lookup(const char *sym)
{
	if (!hash) init_hash();
	ElfW(Sym) *found_sym = NULL;
	if (hash)
	{
		ElfW(Word) nbucket = hash[0];
		ElfW(Word) nchain = hash[1];
		ElfW(Word) (*buckets)[nbucket] = (void*) &hash[2];
		ElfW(Word) (*chains)[nchain] = (void*) &hash[2 + nbucket];

		unsigned long h = elf64_hash((const unsigned char *) sym);
		ElfW(Word) first_symind = (*buckets)[h % nbucket];
		ElfW(Word) symind = first_symind;
		for (; symind != STN_UNDEF; symind = (*chains)[symind])
		{
			ElfW(Sym) *p_sym = &symtab[symind];
			if (0 == strcmp(&strtab[p_sym->st_name], sym))
			{
				/* match */
				found_sym = p_sym;
				break;
			}
		}
	}
	else
	{
		for (ElfW(Sym) *p_sym = &symtab[0]; (char*) p_sym <= (char*) strtab; ++p_sym)
		{
			if (0 == strcmp(&strtab[p_sym->st_name], sym))
			{
				/* match */
				found_sym = p_sym;
				break;
			}
		}
	}
	
	if (found_sym)
	{
		return (char*) our_load_address + found_sym->st_value;
	} else return NULL;
}

static struct uniqtype *uniqtype_for_syscall(int syscall_num)
{
	const char *syscall_name = syscall_names[syscall_num];
	const char prefix[] = "__ifacetype_";
	char name_buf[SYSCALL_NAME_LEN + sizeof prefix + 1];
	strncpy(name_buf, prefix, sizeof prefix);
	strncat(name_buf + sizeof prefix - 1, syscall_name, sizeof name_buf - sizeof prefix + 1);
	name_buf[sizeof name_buf - 1] = '\0';
	
	void *found_uniqtype = hash_lookup(name_buf);
	assert(found_uniqtype);
	return found_uniqtype;
}

void __attribute__((visibility("protected")))
write_footprint(void *base, size_t len)
{
	write_string("n=");
	raw_write(7, fmt_hex_num(len), 18);
	write_string(" base=");
	raw_write(7, fmt_hex_num((uintptr_t) base), 18);
}

void __attribute__((visibility("protected")))
pre_handling(struct generic_syscall *gsp)
{
	write_string("Performing syscall with opcode: ");
	raw_write(2, fmt_hex_num(gsp->syscall_number), 18);
	write_string("\n");
	
	/* Now walk the footprint. */
	struct uniqtype *call = uniqtype_for_syscall(gsp->syscall_number);
	assert(call);
	assert(UNIQTYPE_IS_SUBPROGRAM(call));
	
	/* Footprint enumeration is a breadth-first search from a set of roots. 
	 * Roots are (address, uniqtype) pairs.
	 * Every pointer argument to the syscall is a root. 
	 * (Note that the syscall arguments themselves don't live in memory,
	 * so we can't start directly from a unique root.)
	 * Following a pointer means adding a new root -- the memory on the end of the pointer. */
	
}

void __attribute__((visibility("protected")))
post_handling(struct generic_syscall *gsp, long int ret)
{
	write_string("Syscall returned value: ");
	raw_write(2, fmt_hex_num(ret), 18);
	write_string("\n");
}

static void *lock_memory(long int addr, unsigned long count, int copy)
{
	void *ptr = (void *) addr;
	if (!ptr) {
		return NULL;
	}

	if (__write_footprints) {
		write_footprint(ptr, count);
	}

#ifdef DEBUG_REMAP
	{
		void *ret = malloc(count);
		if (copy) {
			memcpy(ret, ptr, count);
		} else {
			memset(ret, 0, count);
		}
#ifdef DUMP_SYSCALLS
		write_string("    Replacing guest address: ");
		raw_write(2, fmt_hex_num(addr), 18);
		write_string("\n");
		write_string("    with host address:       ");
		raw_write(2, fmt_hex_num((long int) ret), 18);
		write_string("\n");
#endif // DUMP_SYSCALLS


		return ret;
	}
#else
	return ptr;
#endif
}

static void free_memory(long int host_addr, long int guest_addr, unsigned long count)
{
	void *host_ptr __attribute__((unused)) = (void *) host_addr;
	void *guest_ptr __attribute__((unused)) = (void *) guest_addr;
#ifdef DEBUG_REMAP
	if (!host_ptr) {
		return;
	} else if (host_ptr == guest_ptr) {
		return;
	} else if (count > 0) {
		memcpy(guest_ptr, host_ptr, count);
	}

	free(host_ptr);
#endif
}

#define RESUME resume_from_sigframe( \
		ret, \
		gsp->saved_context, \
		instr_len((unsigned char *) gsp->saved_context->uc.uc_mcontext.rip) \
	)

static void do_exit (struct generic_syscall *gsp, post_handler *post)
{
	long int ret = do_syscall1(gsp);
	post(gsp, ret);
	RESUME;
}

static void do_getpid (struct generic_syscall *gsp, post_handler *post)
{
	long int ret = do_syscall0(gsp);
	post(gsp, ret);
	RESUME;
}

static void do_time (struct generic_syscall *gsp, post_handler *post)
{
	long int ret;
	REPLACE_ARGN(0, sizeof(__kernel_time_t));
	ret = do_syscall1(gsp);
	RESTORE_ARGN(0, sizeof(__kernel_time_t));
	
	post(gsp, ret);

	RESUME;
}

static void do_write (struct generic_syscall *gsp, post_handler *post)
{
	long int ret = do_syscall3(gsp);
	post(gsp, ret);
	RESUME;
}


static void do_read (struct generic_syscall *gsp, post_handler *post)
{
	long int ret;

	REPLACE_ARGN(1, gsp->arg2);
	ret = do_syscall3(gsp);
	RESTORE_ARGN(1, gsp->arg2);

	post(gsp, ret);
	
	RESUME;
}
static void do_open (struct generic_syscall *gsp, post_handler *post)
{
	long int ret;
	ret = do_syscall3(gsp);
	post(gsp, ret);
	RESUME;
}

#define DECL_SYSCALL(x) [SYS_ ## x ] = do_ ## x ,
syscall_replacement *replaced_syscalls[SYSCALL_MAX] = {
	DECL_SYSCALL(read)
	DECL_SYSCALL(write)
	DECL_SYSCALL(open)
	DECL_SYSCALL(getpid)
	DECL_SYSCALL(exit)
	DECL_SYSCALL(time)
};
#undef DECL_SYSCALL
