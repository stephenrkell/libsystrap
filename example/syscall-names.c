#include <stddef.h>
#include <sys/syscall.h>
#include "syscall-names.h"

#define SYSCALL(nam) \
[SYS_ ## nam] = #nam,

const char *syscall_names[SYSCALL_MAX + 1] = {
#include "syscall-macros.h"
	NULL
};
