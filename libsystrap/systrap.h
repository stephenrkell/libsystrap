#ifndef SYSTRAP_H_
#define SYSTRAP_H_

#define SYSCALL_MAX 543 /* FIXME: where does this come from? */

void install_sigill_handler(void);
void trap_all_mappings(void);
void trap_one_executable_region(unsigned char *begin, unsigned char *end, const char *filename,
	_Bool is_writable, _Bool is_readable);
void trap_one_instruction_range(unsigned char *begin, unsigned char *end, 
	_Bool is_writable, _Bool is_readable);

struct ibcs_sigframe; /* opaque */

struct generic_syscall {
	struct ibcs_sigframe *saved_context;
	int syscall_number;
	long int args[6];
};

/* for accessing members of mcontext_t */
#ifdef __FreeBSD__
#define MC_REG(x) mc_ ## x
#else
#define MC_REG(x) x
#endif

typedef void post_handler(struct generic_syscall *s, long int ret);
typedef void /*(__attribute__((noreturn))*/ syscall_replacement/*)*/(
	struct generic_syscall *s, 
	post_handler *post
);

extern syscall_replacement *replaced_syscalls[SYSCALL_MAX];

#endif
