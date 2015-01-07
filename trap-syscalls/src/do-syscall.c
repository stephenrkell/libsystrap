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
	long int ret = replaced_syscalls[gsp->syscall_number] ?
			replaced_syscalls[gsp->syscall_number](gsp)
			: do_real_syscall(gsp);
	post_handling(gsp, ret);

	return ret;
}
long int do_real_syscall (struct generic_syscall *gsp)
{
	return do_syscall6(gsp);
}
