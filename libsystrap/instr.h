#ifndef INSTR_H_
#define INSTR_H_


#define PACKAGE "The binutils maintainers suck"
#define HAVE_STRINGSIZE


#ifdef __cplusplus
extern "C"
{
#endif
	
unsigned long instr_len(unsigned const char *ins, unsigned const char *end);
int is_syscall_instr(unsigned const char *ins, unsigned const char *end);

#ifdef __cplusplus
} /* end extern "C" */
#endif

#endif
