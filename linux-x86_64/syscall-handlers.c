/*
 * syscall-handlers.c
 *
 * This provides the implementations of the various functions to be
 * substituted to the performing of the system calls.
 */
#include <string.h>
#include <malloc.h>

#include "trap-syscalls.h"
#include "do-syscall.h"
#include "syscall-handlers.h"
#include "raw-syscalls.h"
#include "syscall-structs.h"

#define PERFORM_SYSCALL	     \
	  FIX_STACK_ALIGNMENT "   \n\
	  movq %[op], %%rax       \n\
	  syscall		 \n\
	 "UNFIX_STACK_ALIGNMENT " \n\
	  movq %%rax, %[ret]      \n"

#define REPLACE_ARGN(n_arg, count)				      \
	long int arg ## n_arg = gsp->arg ## n_arg ;		     \
	gsp->arg ## n_arg =					     \
		(long int) lock_memory(arg ## n_arg , (count), 0);

#define RESTORE_ARGN(n_arg, count)				      \
	free_memory(gsp->arg ## n_arg, arg ## n_arg, (count));	  \
	gsp->arg ## n_arg = arg ## n_arg;

static void write_footprint(void *base, size_t len)
{
	write_string("n=");
	raw_write(7, fmt_hex_num(len), 18);
	write_string(" base=");
	raw_write(7, fmt_hex_num((uintptr_t) base), 18);
}

void pre_handling (struct generic_syscall *gsp)
{
	write_string("Performing syscall with opcode: ");
	raw_write(2, fmt_hex_num(gsp->syscall_number), 18);
	write_string("\n");
}

void post_handling (struct generic_syscall *gsp, long int ret)
{
	write_string("Syscall returned value: ");
	raw_write(2, fmt_hex_num(ret), 18);
	write_string("\n");
}

/*
 * The x86-64 syscall argument passing convention goes like this:
 * RAX: syscall_number
 * RDI: ARG0
 * RSI: ARG1
 * RDX: ARG2
 * R10: ARG3
 * R8:  ARG4
 * R9:  ARG5
 */
long int __attribute__((noinline)) do_syscall0 (struct generic_syscall *gsp)
{
	long int ret;

	__asm__ volatile (PERFORM_SYSCALL
	  : [ret] "=r" (ret)
	  : [op]  "rm" ((long int) gsp->syscall_number)
	  : "r12", SYSCALL_CLOBBER_LIST);

	return ret;
}

long int __attribute__((noinline)) do_syscall1 (struct generic_syscall *gsp)
{
	long int ret;

#ifdef DUMP_SYSCALLS
	write_string("Passing arguments:	      ");
	raw_write(2, fmt_hex_num(gsp->arg0), 18);
	write_string("\n");
#endif

	__asm__ volatile ("movq %[arg0], %%rdi \n"
			   PERFORM_SYSCALL
	  : [ret]  "=r" (ret)
	  : [op]   "rm" ((long int) gsp->syscall_number)
	  , [arg0] "rm" ((long int) gsp->arg0)
	  : "r12", SYSCALL_CLOBBER_LIST);

	return ret;
}

long int __attribute__((noinline)) do_syscall3 (struct generic_syscall *gsp)
{
	long int ret;
	__asm__ volatile ("movq %[arg0], %%rdi \n\
			   movq %[arg1], %%rsi \n\
			   movq %[arg2], %%rdx \n"
			   PERFORM_SYSCALL
	  : [ret]  "=r" (ret)
	  : [op]   "rm" ((long int) gsp->syscall_number)
	  , [arg0] "rm" ((long int) gsp->arg0)
	  , [arg1] "rm" ((long int) gsp->arg1)
	  , [arg2] "rm" ((long int) gsp->arg2)
	  : "r12", SYSCALL_CLOBBER_LIST);

	return ret;
}

/*
 * Here comes do_syscallN for N <- [2..5]
 */

long int __attribute__((noinline)) do_syscall6 (struct generic_syscall *gsp)
{
	long int ret;
	__asm__ volatile ("movq %[arg0], %%rdi \n\
			   movq %[arg1], %%rsi \n\
			   movq %[arg2], %%rdx \n\
			   movq %[arg3], %%r10 \n\
			   movq %[arg4], %%r8  \n\
			   movq %[arg5], %%r9  \n"
			   PERFORM_SYSCALL
	  : [ret]  "=r" (ret)
	  : [op]   "rm" ((long int) gsp->syscall_number)
	  , [arg0] "rm" ((long int) gsp->arg0)
	  , [arg1] "rm" ((long int) gsp->arg1)
	  , [arg2] "rm" ((long int) gsp->arg2)
	  , [arg3] "rm" ((long int) gsp->arg3)
	  , [arg4] "rm" ((long int) gsp->arg4)
	  , [arg5] "rm" ((long int) gsp->arg5)
	  : "r12", SYSCALL_CLOBBER_LIST);

	return ret;
}

static void *lock_memory(long int addr, size_t count, int copy)
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

static void free_memory(long int host_addr, long int guest_addr, size_t count)
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

static long int do_exit (struct generic_syscall *gsp)
{
	return do_syscall1(gsp);
}

static long int do_getpid (struct generic_syscall *gsp)
{
	return do_syscall0(gsp);
}

static long int do_time (struct generic_syscall *gsp)
{
	long int ret;

	REPLACE_ARGN(0, sizeof(__kernel_time_t));

	ret = do_syscall1(gsp);

	RESTORE_ARGN(0, sizeof(__kernel_time_t));

	return ret;
}

static long int do_write (struct generic_syscall *gsp)
{
	return do_syscall3(gsp);
}


static long int do_read (struct generic_syscall *gsp)
{
	long int ret;

	REPLACE_ARGN(1, gsp->arg2);

	ret = do_syscall3(gsp);

	RESTORE_ARGN(1, gsp->arg2);

	return ret;
}
static long int do_open (struct generic_syscall *gsp)
{
	long int ret;
	ret = do_syscall3(gsp);
	return ret;
}

long int (*replaced_syscalls[SYSCALL_MAX])(struct generic_syscall *) = {
	DECL_SYSCALL(read)
	DECL_SYSCALL(write)
	DECL_SYSCALL(open)
	DECL_SYSCALL(getpid)
	DECL_SYSCALL(exit)
	DECL_SYSCALL(time)
};
