/*
 * raw-syscalls.c
 *
 * This contains hand implementations of the system calls required by the
 * trap-syscall library.
 */

#include "do-syscall.h"

#include <stdlib.h>
#include <sys/syscall.h>

void (__attribute__((noreturn)) raw_exit)(int status)
{
	DO_EXIT_SYSCALL(status);
	__builtin_unreachable();
}

int __attribute__((noinline)) raw_open(const char *pathname, int flags, int mode)
{
	struct generic_syscall gs = MKGS3(SYS_open, pathname, flags, mode);
	return do_syscall3(&gs);
}

int __attribute__((noinline)) raw_openat(int dirfd, const char *pathname, int flags, int mode)
{
	struct generic_syscall gs = MKGS4(SYS_openat, dirfd, pathname, flags, mode);
	return do_syscall4(&gs);
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

int __attribute__((noinline)) raw_gettid(void)
{
	struct generic_syscall gs = MKGS0(SYS_gettid);
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

#if 0
#ifdef __i386__
int __attribute__((noinline)) raw_sigaction(int signum, const struct __asm_sigaction *act,
		     struct __asm_sigaction *oldact)
{
	/* This one is slightly different because it gets an extra argument */
	struct generic_syscall gs = MKGS4(SYS_sigaction, signum, act, oldact, sizeof (__asm_sigset_t));
	return do_syscall4(&gs);
}
#endif
#endif

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

/* NOTE that glibc's brk wrapper returns int, but the raw brk returns void*. */
void *__attribute__((noinline)) raw_brk(void *addr)
{
	struct generic_syscall gs = MKGS1(SYS_brk, addr);
	return (void*) do_syscall1(&gs);
}

int sleep_quick(int n)
{
	struct __asm_timespec req = (struct __asm_timespec) { .tv_sec = n };
	int ret = raw_nanosleep(&req, NULL);
	return ret;
}

