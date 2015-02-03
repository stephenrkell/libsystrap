#include <stddef.h>
#include <sys/syscall.h>

#define SYSCALL(n) \
[__NUM_ ## n] = #n,

const char *syscall_names[] = {
#include "linux-syscall-macros.h"
	NULL
};
