#ifndef __SYSCALL_HANDLERS_H__
#define __SYSCALL_HANDLERS_H__

#define SYSCALL_MAX 543
#define DECL_SYSCALL(x) [SYS_ ## x ] = do_ ## x ,

extern long int (*syscalls[SYSCALL_MAX])(struct generic_syscall *);

#endif // __SYSCALL_HANDLERS_H__
