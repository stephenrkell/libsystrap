#ifndef __SYSCALL_HANDLERS_H__
#define __SYSCALL_HANDLERS_H__

#include "do-syscall.h"

#define SYSCALL_MAX 543
#define DECL_SYSCALL(x) [SYS_ ## x ] = do_ ## x ,

#define DEBUG_REMAP

void pre_handling (struct generic_syscall *gsp);
void post_handling (struct generic_syscall *gsp, long int ret);

extern long int (*syscalls[SYSCALL_MAX])(struct generic_syscall *);

#endif // __SYSCALL_HANDLERS_H__
