// #include <unistd.h>

#include "do_syscall.h"
#include "syscall_handlers.h"

long int do_syscall (struct syscall *sys)
{
        struct generic_syscall *gsp = (struct generic_syscall *) sys;
        long ret = syscalls[sys->syscall_number](gsp);

        return ret;
}
