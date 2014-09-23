#ifndef __DO_SYSCALL_H__
#define __DO_SYSCALL_H__

// #include <sys/syscall.h>
#include <unistd.h> /* For some of the types. */
#include <asm/types.h>
#include <asm/posix_types.h>
/*
 * This is quite a bad workaround. Importing the proper headers creates
 * bad namespace collisions though. Not given much thought to how to
 * solve this yet.
 * 
 * srk adds: it shouldn't be necessary to include libc headers. Most
 * of the typedefs (etc) that we need will be in /usr/include/asm,
 * /usr/include/linux/ and /usr/include/<arch>.
 * In this case, __kernel_time_t (defined in /usr/include/asm-generic/posix_types.h,
 * included from /usr/include/x86_64-linux-gnu/asm/posix_types.h)
 * is the definition to use. Note that man pages (even in section 2) are not
 * very reliable, since they document the libc wrapper's signature and not
 * the actual system call.
 */
//typedef long time_t;


/* srk: a similar hack. In this case it seems unavoidable since on my machine
 * I can't find a header defining umode_t. */
typedef unsigned short umode_t;

#define __user

#define PADDED(x) x; long : 0;

#define DUMP_SYSCALLS
#define DEBUG_REMAP

/*
 * Syscall arguments structures
 *
 * These should be, ultimately, mostly auto-generated from the syscall
 * headers file, BSD-style.
 */
struct sys_read_args {
        PADDED(int fd)
        PADDED(void *buf)
        PADDED(size_t count)
};
struct sys_write_args {
        PADDED(int fd)
        PADDED(const void *buf)
        PADDED(size_t count)
};
struct sys_open_args {
        PADDED(const char __user* filename)
        PADDED(int flags)
        PADDED(umode_t mode)
};
struct sys_getpid_args {
};
struct sys_exit_args {
        PADDED(int status)
};
struct sys_time_args {
        PADDED(__kernel_time_t __user *tloc)
};

/*
 * This is the main argument of the do_syscall function.
 * It is mostly a big union of all the possible syscall arguments,
 * plus the syscall number.
 */
struct syscall {
        PADDED(int syscall_number)
        union {
                struct sys_read_args sys_read_args;
                struct sys_write_args sys_write_args;
                struct sys_open_args sys_open_args;
                struct sys_getpid_args sys_getpid_args;
                struct sys_exit_args sys_exit_args;
                struct sys_time_args sys_time_args;
        } syscall_args;
};

struct generic_syscall {
        PADDED(int syscall_number)
        PADDED(long int arg0)
        PADDED(long int arg1)
        PADDED(long int arg2)
        PADDED(long int arg3)
        PADDED(long int arg4)
        PADDED(long int arg5)
};

/*
 * Main function
 */
long int do_syscall (struct syscall *sys);

#endif // __DO_SYSCALL_H__
