#include "raw-syscalls-asm.h"
#include <sys/syscall.h>

typedef long time_t;

int _start (void)
{
	time_t t;
	long int ret;

	__asm__ volatile (
	"mov _r_debug,  %%"stringifx(argreg0)"  \n\
	 mov %[addr_t], %%"stringifx(argreg0)"  \n\
	"stringifx(SYSCALL_INSTR)"              \n\
	 mov %%"stringifx(argreg0)",     %[ret] \n"
	: [ret] "=r" (ret)
	: [addr_t] "rm" (&t),
	  [nr] "a" (__NR_time)
	: SYSCALL_CLOBBER_LIST(1));

	__asm__ volatile (
	 stringifx(SYSCALL_INSTR)"              \n"
	: 
	: [t] cargreg0 (ret & 0x7f),
	  [nr] "a" (__NR_exit)
	: 
#ifndef __x86_64__ /* can't clobber a register we also use, in the cargreg0/"D" constraint */
			SYSCALL_CLOBBER_LIST(1)
#endif
	);

	return 0;
}
