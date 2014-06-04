#ifndef __DO_SYSCALL_H__
#define __DO_SYSCALL_H__

#include <sys/syscall.h>

#define __user

#define PADDED(x) x; long : 0;

/*
 * Syscall arguments structures
 *
 * These should be, ultimately, mostly auto-generated from the syscall
 * headers file, BSD-style.
 */
struct sys_exit_args {
        PADDED(int status)
};

/*
 * This is the main argument of the do_syscall function.
 * It is mostly a big union of all the possible syscall arguments,
 * plus the syscall number.
 */
struct syscall {
        PADDED(int syscall_number)
        union {
                struct sys_exit_args sys_exit_args;
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

static inline void panic (void)
{
        while(1) ;
}

#endif // __DO_SYSCALL_H__
