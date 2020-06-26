#ifndef RAW_SYSCALL_DEFS_H_
#define RAW_SYSCALL_DEFS_H_

struct __asm_sigaction;
struct user_desc;
struct __asm_timespec;
struct stat;
extern void restore_rt(void) __asm__("__restore_rt"); /* in restorer.c */

void raw_exit(int status) __attribute__((noreturn));
int raw_open(const char *pathname, int flags) __attribute__((noinline));
int raw_fstat(int fd, struct stat *buf) __attribute__((noinline));
int raw_stat(char *filename, struct stat *buf) __attribute__((noinline));
int raw_nanosleep(struct __asm_timespec *req,
		struct __asm_timespec *rem) __attribute__((noinline));
int raw_getpid(void) __attribute__((noinline));
int raw_kill(pid_t pid, int sig) __attribute__((noinline));
int raw_read(int fd, void *buf, size_t count) __attribute__((noinline));
ssize_t raw_write(int fd, const void *buf,
		size_t count) __attribute__((noinline));
int raw_close(int fd) __attribute__((noinline));
int raw_mprotect(const void *addr, size_t len,
		int prot) __attribute__((noinline));
#ifndef MMAP_RETURN_IS_ERROR
#define MMAP_RETURN_IS_ERROR(p) \
        (((unsigned long long)(void*)-1 - (unsigned long long)(p)) < MIN_PAGE_SIZE)
#endif

void *raw_mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset);
int raw_munmap(void *addr, size_t length);
void *__attribute__((noinline)) raw_mremap(void *old_address, size_t old_size,
                    size_t new_size, int flags, void *new_address);
int raw_rt_sigaction(int signum, const struct __asm_sigaction *act,
		     struct __asm_sigaction *oldact) __attribute__((noinline));
void *raw_mremap(void *old_address, size_t old_size,
    size_t new_size, int flags, void *new_address);
int raw_brk(void *addr);

struct user_desc;
int __attribute__((noinline)) raw_set_thread_area(struct user_desc *u_info);
int __attribute__((noinline)) raw_arch_prctl(int code, unsigned long addr);

/* Some utilities for our clients. */
#define write_string(s) raw_write(2, (s), sizeof (s) - 1)
#define write_chars(s, t)  raw_write(2, s, t - s)
#define write_ulong(a)   raw_write(2, fmt_hex_num((a)), 18)
const char *fmt_hex_num(unsigned long n);
int sleep_quick(int n);

struct generic_syscall;
/* This is defined in do-syscall.c, but do-syscall.h is not a public header. */
void *generic_syscall_get_ip(struct generic_syscall *gsp);

#endif
