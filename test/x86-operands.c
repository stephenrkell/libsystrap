#define _GNU_SOURCE
#include "instr.h"
#include <stdio.h>
#include <ucontext.h>

static void saw_operand(int type, unsigned int bytes, uint32_t *val,
		unsigned long *p_reg, int *p_mem_seg, unsigned long *p_mem_off,
		void *arg)
{
	printf("Saw an operand %d, %u, %p, %p, %p, %p\n", type, bytes, val,
		p_reg, p_mem_seg, p_mem_off);
}

int main(void)
{
	ucontext_t c;
	int ret = getcontext(&c);
	printf("Context has rdx %lx, rax %lx\n", 
		(unsigned long) c.uc_mcontext.gregs[REG_RDX], 
		(unsigned long) c.uc_mcontext.gregs[REG_RAX]);
	/* in that context, enumerate an instruction's operands */
	enumerate_operands((unsigned const char *) &&label, (unsigned char *) &&label + 16,
		&c.uc_mcontext,
		saw_operand,
		NULL
		);
	ret:
	return 0;
	label:
		__asm__ volatile ("mov    %%rax,%%rdx");
}
