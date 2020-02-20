#include <stddef.h>
#include <sys/syscall.h>

#define SYSCALL(n) \
[SYS_ ## n] = #n,

const char *syscall_names[] = {
#include "syscall-macros.h"
	NULL
};
