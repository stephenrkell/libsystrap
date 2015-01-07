#ifndef __DO_SYSCALL_H__
#define __DO_SYSCALL_H__

#define PADDED(x) x; long : 0;

struct generic_syscall {
	int syscall_number;
	long int arg0;
	long int arg1;
	long int arg2;
	long int arg3;
	long int arg4;
	long int arg5;
};

long int do_syscall (struct generic_syscall *sys);
long int do_real_syscall (struct generic_syscall *sys);

#endif // __DO_SYSCALL_H__
