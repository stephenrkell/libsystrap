#ifndef INSTR_H_
#define INSTR_H_


#define PACKAGE "The binutils maintainers suck"
#define HAVE_STRINGSIZE

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

unsigned long instr_len(unsigned const char *ins, unsigned const char *end);
int is_syscall_instr(unsigned const char *ins, unsigned const char *end);
int enumerate_operands(unsigned const char *ins, unsigned const char *end,
	void *mcontext,
	void (*saw_operand)(int /*type*/, unsigned int /*bytes*/, uint32_t */*val*/,
		unsigned long */*p_reg*/, int */*p_mem_seg*/, unsigned long */*p_mem_off*/,
		void */*arg*/),
	void *arg
	);

#ifdef __cplusplus
} /* end extern "C" */
#endif

#endif
