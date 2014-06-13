// #include <unistd.h>

#include "do_syscall.h"
#include "syscall_handlers.h"
#include "raw_syscalls.h"

long int do_syscall (struct syscall *sys)
{
        struct generic_syscall *gsp = (struct generic_syscall *) sys;

#ifdef DUMP_SYSCALLS
        write_string("Performing syscall with opcode: ");
	raw_write(2, fmt_hex_num(gsp->syscall_number), 18);
	write_string("\n");
#endif

        long int ret = syscalls[sys->syscall_number](gsp);

#ifdef DUMP_SYSCALLS
        write_string("Syscall returned value: ");
        raw_write(2, fmt_hex_num(ret), 18);
        write_string("\n");
#endif

        return ret;
}
