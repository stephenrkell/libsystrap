#define _GNU_SOURCE
#include <linux/unistd.h>
#include <asm/ldt.h>
#include <sys/mman.h>
#include <sched.h>
#include <stdlib.h>
#include <stdint.h>

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
	the_stack = (void*)((uintptr_t) the_stack + (4096 & 0xfff0));

	int tid = clone(the_function,
		the_stack,
		flags,
		&the_arg);

	if (tid != 0) while (the_arg != 42);

	return 0;
}
