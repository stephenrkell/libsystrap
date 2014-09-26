#ifndef __DO_SYSCALL_H__
#define __DO_SYSCALL_H__

#define PADDED(x) x; long : 0;

struct generic_syscall {
        PADDED(int syscall_number)
        PADDED(long int arg0)
        PADDED(long int arg1)
        PADDED(long int arg2)
        PADDED(long int arg3)
        PADDED(long int arg4)
        PADDED(long int arg5)
};

long int do_syscall (struct generic_syscall *sys);

#endif // __DO_SYSCALL_H__
