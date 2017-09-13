#ifndef INSTR_H_
#define INSTR_H_

#define PACKAGE "NOT binutils"
#define HAVE_STRINGSIZE

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/* HACK: include this from somewhere else, please. */
enum dwarf_regs_x86_64
{
	DWARF_X86_64_RAX     = 0,
	DWARF_X86_64_RDX     = 1,
	DWARF_X86_64_RCX     = 2,
	DWARF_X86_64_RBX     = 3,
	DWARF_X86_64_RSI     = 4,
	DWARF_X86_64_RDI     = 5,
	DWARF_X86_64_RBP     = 6,
	DWARF_X86_64_RSP     = 7,
	DWARF_X86_64_R8      = 8,
	DWARF_X86_64_R9      = 9,
	DWARF_X86_64_R10     = 10,
	DWARF_X86_64_R11     = 11,
	DWARF_X86_64_R12     = 12,
	DWARF_X86_64_R13     = 13,
	DWARF_X86_64_R14     = 14,
	DWARF_X86_64_R15     = 15,
	DWARF_X86_64_RIP     = 16
};

unsigned long instr_len(unsigned const char *ins, unsigned const char *end);
int is_syscall_instr(unsigned const char *ins, unsigned const char *end);
int enumerate_operands(unsigned const char *ins, unsigned const char *end,
	void *mcontext,
	void (*saw_operand)(int /*type*/, unsigned int /*bytes*/, uint32_t */*val*/,
		unsigned long */*p_reg*/, int */*p_mem_seg*/, unsigned long */*p_mem_off*/,
		int */*p_fromreg1*/, int */*p_fromreg2*/, void */*arg*/),
	void *arg
	);

#ifdef __cplusplus
} /* end extern "C" */
#endif

#endif
