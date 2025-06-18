#define _GNU_SOURCE
#include <linux/unistd.h>
#include <asm/ldt.h>
#include <sys/mman.h>
#include <sched.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <err.h>
#include <string.h>
#include <strings.h>

static int the_function(void *arg)
{
	*(int _Atomic*)arg = 42;
	for(;;); /* returning is pointless; just wait for the main thread to exit */
}

int the_arg = 0;
void _start(void)
{
	unsigned flags = CLONE_VM | CLONE_FILES | CLONE_IO | CLONE_THREAD | CLONE_SIGHAND;

	void *the_stack_base = mmap(NULL, 8192, PROT_READ|PROT_WRITE,
		MAP_PRIVATE|MAP_ANONYMOUS|MAP_GROWSDOWN, -1, 0);
	if (the_stack_base == MAP_FAILED) exit(1);
	void *the_stack = (void*)((uintptr_t) the_stack_base + (8192 - sizeof (void*)));

	typedef uint64_t u64;
// from the man page
         struct clone_args {
               u64 flags;        /* Flags bit mask */
               u64 pidfd;        /* Where to store PID file descriptor
                                    (pid_t *) */
               u64 child_tid;    /* Where to store child TID,
                                    in child's memory (pid_t *) */
               u64 parent_tid;   /* Where to store child TID,
                                    in parent's memory (int *) */
               u64 exit_signal;  /* Signal to deliver to parent on
                                    child termination */
               u64 stack;        /* Pointer to lowest byte of stack */
               u64 stack_size;   /* Size of stack */
               u64 tls;          /* Location of new TLS */
               u64 set_tid;      /* Pointer to a pid_t array
                                    (since Linux 5.5) */
               u64 set_tid_size; /* Number of elements in set_tid
                                    (since Linux 5.5) */
               u64 cgroup;       /* File descriptor for target cgroup
                                    of child (since Linux 5.7) */
           };

	struct clone_args args = (struct clone_args) {
		.flags = ((u64) flags) & ~0xff,
		.stack = /* LOWEST byte! */ (u64) the_stack_base,
		.stack_size = 8192
	};
	fprintf(stdout, "Cloning with clone3() a thread to run %p using new 4kB stack "
		"with topmost address %p, base %p, flags %lx\n",
		the_function, the_stack, args.stack, args.flags);
	fflush(stdout);

	/* Note that 'fn' and 'arg' are handled in the glibc wrapper, not in
	 * the actual clone() call which behaves like fork(). So we have to emulate this
	 * below. */

	//int tid = clone(
	//	the_function /* fn */,
	//	the_stack /* stack */,
	//	flags /* flags */,
	//	&the_arg /* arg */);
#ifndef SYS_clone3
#define SYS_clone3 435
#endif
	/* calling syscall() can never work here, because
	 * it relies on the stack and we are about to zap it.
	 * We have to do the syscall in inline asm. And since
     * we want to read nr_tid later, it must be in a register.
     * The compiler must not try to reload it from the stack. */
	register int nr_tid asm("r12") = SYS_clone3;
	__asm__ ("syscall" 
                       : "+a"(nr_tid)
	                   : /*rdi*/"D"(&args), /*rsi*/"S"(sizeof args));
	if (nr_tid == 0)
	{
		the_function(&the_arg); // DOES return
	}
	else if (nr_tid != -1) while (the_arg != 42);
	else
	{
		err(EXIT_FAILURE, "could not clone3()");
	}

	exit(0);
}
