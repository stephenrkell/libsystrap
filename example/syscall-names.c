#include <stddef.h>
#include <sys/syscall.h>

#define SYSCALL(nam) \
[SYS_ ## nam] = #nam,

#ifndef SYSCALL_MAX
#define SYSCALL_MAX 1024
#endif

const char *syscall_names[SYSCALL_MAX + 2] = {
#include "syscall-macros.h"
	NULL
};
