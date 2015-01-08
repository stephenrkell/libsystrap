#ifndef __RAW_SYSCALLS_H__
#define __RAW_SYSCALLS_H__

#include <unistd.h>
#include <asm-generic/stat.h>
#include <sys/syscall.h>
#include <asm/signal.h>
#include <asm/fcntl.h>
#include <sys/mman.h>
#include <stdint.h>

/* Our callee-save registers are
 *	 rbp, rbx, r12, r13, r14, r15
 * but all others need to be in the clobber list.
 *	 rdi, rsi, rax, rcx, rdx, r8, r9, r10, r11
 *	 xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15
 *	 condition codes, memory
 */
#define SYSCALL_CLOBBER_LIST \
	"%rdi", "%rsi", "%rax", "%rcx", "%rdx", "%r8", "%r9", "%r10", "%r11", \
	"%xmm0", "%xmm1", "%xmm2", "%xmm3", "%xmm4", "%xmm5", "%xmm6", "%xmm7", "%xmm8", \
	"%xmm9", "%xmm10", "%xmm11", "%xmm12", "%xmm13", "%xmm14", "%xmm15", \
	"cc" /*, "memory" */
#define FIX_STACK_ALIGNMENT \
	"movq %%rsp, %%rax\n\
	 andq $0xf, %%rax    # now we have either 8 or 0 in rax \n\
	 subq %%rax, %%rsp   # fix the stack pointer \n\
	 movq %%rax, %%r12   # save the amount we fixed it up by in r12 \n\
	 "

#define UNFIX_STACK_ALIGNMENT \
	"addq %%r12, %%rsp\n"

#define stringify(cond) #cond

#define assert(cond) \
	do { ((cond) ? ((void) 0) : (__assert_fail("Assertion failed: \"" stringify((cond)) "\"", __FILE__, __LINE__, __func__ ))); }  while (0)

#define write_string(s) raw_write(2, (s), sizeof (s) - 1)
#define write_chars(s, t)  raw_write(2, s, t - s)
#define write_ulong(a)   raw_write(2, fmt_hex_num((a)), 18)

void raw_exit(int status) __attribute__((noreturn));
int raw_open(const char *pathname, int flags) __attribute__((noinline));
int raw_fstat(int fd, struct stat *buf) __attribute__((noinline));
int raw_nanosleep(struct timespec *req,
		struct timespec *rem) __attribute__((noinline));
int raw_read(int fd, void *buf, size_t count) __attribute__((noinline));
ssize_t raw_write(int fd, const void *buf,
		size_t count) __attribute__((noinline));
int raw_close(int fd) __attribute__((noinline));
int raw_mprotect(const void *addr, size_t len,
		int prot) __attribute__((noinline));
int raw_rt_sigaction(int signum, const struct sigaction *act,
		     struct sigaction *oldact) __attribute__((noinline));
void __assert_fail(const char *assertion, const char *file,
                   unsigned int line, const char *function) __attribute__((noreturn));
const char *fmt_hex_num(unsigned long n);

#endif // __RAW_SYSCALLS_H__
