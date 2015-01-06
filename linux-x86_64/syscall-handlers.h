#ifndef __SYSCALL_HANDLERS_H__
#define __SYSCALL_HANDLERS_H__

#include "do-syscall.h"

#define SYSCALL_MAX 543
#define DECL_SYSCALL(x) [SYS_ ## x ] = do_ ## x ,

#define DEBUG_REMAP

void pre_handling (struct generic_syscall *gsp);
void post_handling (struct generic_syscall *gsp, long int ret);

long int __attribute__((noinline)) do_syscall6 (struct generic_syscall *gsp);
long int __attribute__((noinline)) do_syscall5 (struct generic_syscall *gsp);
long int __attribute__((noinline)) do_syscall4 (struct generic_syscall *gsp);
long int __attribute__((noinline)) do_syscall3 (struct generic_syscall *gsp);
long int __attribute__((noinline)) do_syscall2 (struct generic_syscall *gsp);
long int __attribute__((noinline)) do_syscall1 (struct generic_syscall *gsp);
long int __attribute__((noinline)) do_syscall0 (struct generic_syscall *gsp);

extern long int (*replaced_syscalls[SYSCALL_MAX])(struct generic_syscall *);

#endif // __SYSCALL_HANDLERS_H__
