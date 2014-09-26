/*
 * do-syscall.c
 *
 * This file contains the do_syscall() function, which performs the
 * action expected from the trapped system call.
 */

#include "do-syscall.h"
#include "syscall-handlers.h"

long int do_syscall (struct generic_syscall *gsp)
{
        pre_handling(gsp);
        long int ret = syscalls[gsp->syscall_number](gsp);
        post_handling(gsp, ret);

        return ret;
}
