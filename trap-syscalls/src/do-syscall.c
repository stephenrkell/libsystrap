/*
 * Implementations of various substitution functions and helper functions
 * called during syscall emulation.
 */

#include "do-syscall.h"

#define REPLACE_ARGN(n_arg, count)				      \
	long int arg ## n_arg = gsp->arg ## n_arg ;		     \
	gsp->arg ## n_arg =					     \
		(long int) lock_memory(arg ## n_arg , (count), 0);

#define RESTORE_ARGN(n_arg, count)				      \
	free_memory(gsp->arg ## n_arg, arg ## n_arg, (count));	  \
	gsp->arg ## n_arg = arg ## n_arg;

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
	void *host_ptr = (void *) host_addr;
	void *guest_ptr = (void *) guest_addr;
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
