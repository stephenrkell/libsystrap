#define _GNU_SOURCE
#include <linux/unistd.h>
#include <asm/ldt.h>
#include <sys/mman.h>
#include <sched.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

static int the_function(void *arg)
{
	return (*(int*)arg = 42);
}

int main(void)
{
	int the_arg = 0;
	int flags = CLONE_VM | CLONE_FILES | CLONE_IO | CLONE_THREAD | CLONE_SIGHAND;

	void *the_stack = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
		MAP_PRIVATE|MAP_ANONYMOUS|MAP_GROWSDOWN, -1, 0);
	if (the_stack == MAP_FAILED) exit(1);

	/* I've found that we can get weird crashes on clone if the new stack is not
	 * aligned correctly. I've seen crashes from address 0x1 and from address 0x0.
	 * I thought that perhaps the kernel is truncating the address and so the stack
	 * is getting misaligned by 8 bytes. However, that doesn't quite check out because
	 * the null pointer has been literally the $rip on the fresh thread's return from
	 * clone, i.e. before it looks at the stack. */
	the_stack = (void*)((uintptr_t) the_stack + 4096);
	fprintf(stdout, "Cloning a thread to run %p using new 4kB stack with topmost address %p\n",
		the_function,
		the_stack);
	fflush(stdout);
	int tid = clone(the_function,
		the_stack,
		flags,
		&the_arg);

	if (tid != 0) while (the_arg != 42);

	return 0;
}
