#include <stddef.h>
#include <sys/syscall.h>

#define SYSCALL(nam, num) \
[SYS_ ## nam] = #nam,

const char *syscall_names[] = {
#include "syscall-macros.h"
	NULL
};
