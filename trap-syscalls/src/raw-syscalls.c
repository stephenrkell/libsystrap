/*
 * raw-syscalls.c
 *
 * This contains hand implementations of the system calls required by the
 * trap-syscall library.
 */

#include "raw-syscalls.h"
#define DO_EXIT_SYSCALL \
	long retcode = 0; \
	op = SYS_exit; \
	__asm__ volatile ("movq %0, %%rdi      # \n\
			  "FIX_STACK_ALIGNMENT " \n\
			   movq %1, %%rax      # \n\
			   syscall	     # do the syscall \n\
			  "UNFIX_STACK_ALIGNMENT " \n" \
	  : /* no output*/ : "rm"(retcode), "rm"(op) : "r12", SYSCALL_CLOBBER_LIST);

void (__attribute__((noreturn)) raw_exit)(int status)
{
	long int op;
	DO_EXIT_SYSCALL;
	__builtin_unreachable();
}

int __attribute__((noinline)) raw_open(const char *pathname, int flags)
{
	long int ret;
	long int op = SYS_open;
	long int longflags = flags;

	/* We have to do it all in one big asm statement, since the compiler
	 * can change what's in registers in between asm statements. */
	__asm__ volatile ("movq %1, %%rdi      # \n\
			   movq %2, %%rsi      # \n\
			  "FIX_STACK_ALIGNMENT " \n\
			   movq %3, %%rax      # \n\
			   syscall	     # do the syscall \n\
			  "UNFIX_STACK_ALIGNMENT " \n\
			   movq %%rax, %0\n"
	  : "=r"(ret) : "rm"(pathname), "rm"(longflags), "rm"(op) : "r12", SYSCALL_CLOBBER_LIST);
	return ret;
}

int __attribute__((noinline)) raw_fstat(int fd, struct stat *buf)
{
	long int ret;
	long int op = SYS_fstat;
	long int long_fd = fd;

	/* We have to do it all in one big asm statement, since the compiler
	 * can change what's in registers in between asm statements. */
	__asm__ volatile ("movq %1, %%rdi      # \n\
			   movq %2, %%rsi      # \n\
			  "FIX_STACK_ALIGNMENT " \n\
			   movq %3, %%rax      # \n\
			   syscall	     # do the syscall \n\
			  "UNFIX_STACK_ALIGNMENT " \n\
			   movq %%rax, %0\n"
	  : "=r"(ret) : "rm"(long_fd), "rm"(buf), "rm"(op) : "r12", SYSCALL_CLOBBER_LIST);
	return ret;
}

int __attribute__((noinline)) raw_nanosleep(struct timespec *req,
			struct timespec *rem)
{
	long int ret;
	long int op = SYS_nanosleep;

	/* We have to do it all in one big asm statement, since the compiler
	 * can change what's in registers in between asm statements. */
	__asm__ volatile ("movq %1, %%rdi      # \n\
			   movq %2, %%rsi      # \n\
			  "FIX_STACK_ALIGNMENT " \n\
			   movq %3, %%rax      # \n\
			   syscall	     # do the syscall \n\
			  "UNFIX_STACK_ALIGNMENT " \n\
			   movq %%rax, %0\n"
	  : "=r"(ret) : "rm"(req), "rm"(rem), "rm"(op) : "r12", SYSCALL_CLOBBER_LIST);
	return ret;
}

int __attribute__((noinline)) raw_read(int fd, void *buf, size_t count)
{
	long int ret;
	long int op = SYS_read;
	long int longfd = fd;
	__asm__ volatile ("movq %1, %%rdi      # \n\
			   movq %2, %%rsi      # \n\
			   movq %3, %%rdx      # \n\
			  "FIX_STACK_ALIGNMENT " \n\
			   movq %4, %%rax      # \n\
			   syscall	     # do the syscall \n\
			  "UNFIX_STACK_ALIGNMENT " \n\
			   movq %%rax, %0\n"
	  : "=r"(ret) : "rm"(longfd), "rm"(buf), "rm"(count), "rm"(op) : "r12",  SYSCALL_CLOBBER_LIST);

	return ret;
}

int __attribute__((noinline)) raw_close(int fd)
{
	long int ret;
	long int op = SYS_close;
	long int longfd = fd;
	__asm__ volatile ("movq %1, %%rdi      # \n\
			  "FIX_STACK_ALIGNMENT " \n\
			   movq %2, %%rax      # \n\
			   syscall	     # do the syscall \n\
			  "UNFIX_STACK_ALIGNMENT " \n\
			   movq %%rax, %0\n"
	  : "=r"(ret) : "rm"(longfd), "rm"(op) : "%r12", SYSCALL_CLOBBER_LIST);
	return ret;
}

int __attribute__((noinline)) raw_mprotect(const void *addr, size_t len, int prot)
{
	long int ret;
	long int op = SYS_mprotect;
	long int longprot = prot;
	__asm__ volatile ("movq %1, %%rdi      # \n\
			   movq %2, %%rsi      # \n\
			   movq %3, %%rdx      # \n\
			  "FIX_STACK_ALIGNMENT " \n\
			   movq %4, %%rax      # \n\
			   syscall	     # do the syscall \n\
			  "UNFIX_STACK_ALIGNMENT " \n\
			   movq %%rax, %0\n"
	  : "=r"(ret) : "rm"(addr), "rm"(len), "rm"(longprot), "rm"(op) : "r12",  SYSCALL_CLOBBER_LIST);
	return ret;
}

int __attribute__((noinline)) raw_rt_sigaction(int signum, const struct sigaction *act,
		     struct sigaction *oldact)
{
	long int ret;
	long int op = SYS_rt_sigaction;
	long int longsignum = signum;
	size_t sigsetsize = sizeof (sigset_t);
	__asm__ volatile ("movq %1, %%rdi      # \n\
			   movq %2, %%rsi      # \n\
			   movq %3, %%rdx      # \n\
			   movq %4, %%r10      # \n\
			  "FIX_STACK_ALIGNMENT " \n\
			   movq %5, %%rax      # \n\
			   syscall	     # do the syscall \n\
			  "UNFIX_STACK_ALIGNMENT " \n\
			   movq %%rax, %0\n"
	  : "=r"(ret) : "rm"(longsignum), "rm"(act), "rm"(oldact), "rm"(sigsetsize), "rm"(op) : "r12",  SYSCALL_CLOBBER_LIST);

	return ret;
}

void (__attribute__((noreturn)) __assert_fail)(
	const char *msg, const char *file,
	unsigned int line, const char *function)
{
	long strlen = 0;
	const char *msg_end = msg;
	while (*msg_end++);
	raw_write(2, msg, msg_end - msg - 1);
	raw_exit(128 + /* SIGABRT */ 6);
}

ssize_t __attribute__((noinline)) raw_write(int fd, const void *buf, size_t count)
{
	long int ret;
	long int op = SYS_write;
	long int longfd = fd;
	__asm__ volatile ("movq %1, %%rdi      # \n\
			   movq %2, %%rsi      # \n\
			   movq %3, %%rdx      # \n\
			  "FIX_STACK_ALIGNMENT " \n\
			   movq %4, %%rax      # \n\
			   syscall	     # do the syscall \n\
			  "UNFIX_STACK_ALIGNMENT " \n\
			   movq %%rax, %0\n"
	  : "=r"(ret) : "rm"(longfd), "rm"(buf), "rm"(count), "rm"(op) : "r12",  SYSCALL_CLOBBER_LIST);

	return ret;
}

const char *fmt_hex_num(unsigned long n)
{
	static char buf[19];
	buf[0] = '0';
	buf[1] = 'x';
	signed i_dig = 15;
	do
	{
		unsigned long dig = (n >> (4 * i_dig)) & 0xf;
		buf[2 + 15 - i_dig] = (dig > 9) ? ('a' + dig - 10) : ('0' + dig);
		--i_dig;
	} while (i_dig >= 0);
	buf[18] = '\0';
	return buf;
}
