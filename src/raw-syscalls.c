/*
 * raw-syscalls.c
 *
 * This contains hand implementations of the system calls required by the
 * trap-syscall library.
 */

#include "do-syscall.h"
#define DO_EXIT_SYSCALL \
	long retcode = status; \
	op = SYS_exit; \
	__asm__ volatile ("movq %0, %%rdi      # \n\
			  "FIX_STACK_ALIGNMENT " \n\
			   movq %1, %%rax      # \n\
			   syscall	     # do the syscall \n\
			  "UNFIX_STACK_ALIGNMENT " \n" \
	  : /* no output*/ : "rm"(retcode), "rm"(op) : "r12", SYSCALL_CLOBBER_LIST);

#include <stdlib.h>
#include <sys/syscall.h>

void (__attribute__((noreturn)) raw_exit)(int status)
{
	long int op;
	DO_EXIT_SYSCALL;
	__builtin_unreachable();
}

int __attribute__((noinline)) raw_open(const char *pathname, int flags)
{
	struct generic_syscall gs = MKGS2(SYS_open, pathname, flags);
	return do_syscall2(&gs);
}

int __attribute__((noinline)) raw_fstat(int fd, struct stat *buf)
{
	struct generic_syscall gs = MKGS2(SYS_fstat, fd, buf);
	return do_syscall2(&gs);
}

int __attribute__((noinline)) raw_stat(char *filename, struct stat *buf)
{
	struct generic_syscall gs = MKGS2(SYS_stat, filename, buf);
	return do_syscall2(&gs);
}

int __attribute__((noinline)) raw_nanosleep(struct __asm_timespec *req,
			struct __asm_timespec *rem)
{
	struct generic_syscall gs = MKGS2(SYS_nanosleep, req, rem);
	return do_syscall2(&gs);
}

int __attribute__((noinline)) raw_getpid(void)
{
	struct generic_syscall gs = MKGS0(SYS_getpid);
	return do_syscall0(&gs);
}

int __attribute__((noinline)) raw_kill(__kernel_pid_t pid, int sig)
{
	struct generic_syscall gs = MKGS2(SYS_kill, pid, sig);
	return do_syscall2(&gs);
}

int __attribute__((noinline)) raw_read(int fd, void *buf, size_t count)
{
	struct generic_syscall gs = MKGS3(SYS_read, fd, buf, count);
	return do_syscall3(&gs);
}

int __attribute__((noinline)) raw_close(int fd)
{
	struct generic_syscall gs = MKGS1(SYS_close, fd);
	return do_syscall1(&gs);
}

int __attribute__((noinline)) raw_mprotect(const void *addr, size_t len, int prot)
{
	struct generic_syscall gs = MKGS3(SYS_mprotect, addr, len, prot);
	return do_syscall3(&gs);
}

void *__attribute__((noinline)) raw_mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset)
{
	struct generic_syscall gs = MKGS6(SYS_mmap, addr, length, prot, flags, fd, offset);
	return (void*) do_syscall6(&gs);
}

int __attribute__((noinline)) raw_munmap(void *addr, size_t length)
{
	struct generic_syscall gs = MKGS2(SYS_munmap, addr, length);
	return do_syscall2(&gs);
}

void *__attribute__((noinline)) raw_mremap(void *old_address, size_t old_size,
                    size_t new_size, int flags, void *new_address)
{
	struct generic_syscall gs = MKGS5(SYS_mremap, old_address, old_size, new_size, flags, new_address);
	return (void*) do_syscall5(&gs);
}

int __attribute__((noinline)) raw_rt_sigaction(int signum, const struct __asm_sigaction *act,
		     struct __asm_sigaction *oldact)
{
	/* This one is slightly different because it gets an extra argument */
	struct generic_syscall gs = MKGS4(SYS_rt_sigaction, signum, act, oldact, sizeof (__asm_sigset_t));
	return do_syscall4(&gs);
}

ssize_t __attribute__((noinline)) raw_write(int fd, const void *buf, size_t count)
{
	struct generic_syscall gs = MKGS3(SYS_write, fd, buf, count);
	return do_syscall3(&gs);
}

int __attribute__((noinline)) raw_set_thread_area(struct user_desc *u_info)
{
	struct generic_syscall gs = MKGS1(SYS_set_thread_area, u_info);
	return do_syscall1(&gs);
}

int __attribute__((noinline)) raw_arch_prctl(int code, unsigned long addr)
{
	struct generic_syscall gs = MKGS2(SYS_arch_prctl, code, addr);
	return do_syscall2(&gs);
}

int __attribute__((noinline)) raw_brk(void *addr)
{
	struct generic_syscall gs = MKGS1(SYS_brk, addr);
	return do_syscall1(&gs);
}

#if 0 /* This code seems to be dead */
static void handle_sigabrt(int num)
{
	raw_exit(128 + SIGABRT);
}

static void install_sigabrt_handler(void) __attribute__((constructor));
static void install_sigabrt_handler(void)
{
	struct __asm_sigaction action = {
		.sa_handler = &handle_sigabrt,
		.sa_mask = 0,
		.sa_flags = /*SA_SIGINFO |*/ 0x04000000u /* SA_RESTORER */ | /*SA_RESTART |*/ SA_NODEFER
		#ifndef __FreeBSD__
		, .sa_restorer = restore_rt
		#endif
	};
	int ret = raw_rt_sigaction(SIGABRT, &action, NULL);
	assert(ret == 0);
}

void (__attribute__((noreturn)) __assert_fail)(
	const char *msg, const char *file,
	unsigned int line, const char *function)
{
	const char *msg_end = msg;
	while (*msg_end++);
	raw_write(2, "Assertion failed: ", sizeof "Assertion failed: " - 1);
	raw_write(2, msg, msg_end - msg - 1);
	raw_write(2, "\n", sizeof "\n" - 1);
	raw_kill(raw_getpid(), SIGABRT);
	/* hmm -- SIGABRT might be blocked? okay, try waiting indefinitely */
	while (1) {}
}
#endif

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

int sleep_quick(int n)
{
	struct __asm_timespec req = (struct __asm_timespec) { .tv_sec = n };
	int ret = raw_nanosleep(&req, NULL);
	return ret;
}
