#include <stddef.h>

#define __SYSCALL(num, decl) \
[num] = #decl, 

const char *syscall_names[] = {
#include <asm-generic/unistd.h>
	NULL
};
