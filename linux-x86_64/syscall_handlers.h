#ifndef __SYSCALL_HANDLERS_H__
#define __SYSCALL_HANDLERS_H__

#define SYSCALL_MAX 543
#define DECL_SYSCALL(x) [SYS_ ## x ] = do_ ## x ,
typedef long int (*syscall)(struct generic_syscall *);

extern syscall syscalls[SYSCALL_MAX];

#endif // __SYSCALL_HANDLERS_H__
