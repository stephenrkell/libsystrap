#ifndef SYSTRAP_H_
#define SYSTRAP_H_

#define SYSCALL_MAX 543 /* FIXME: where does this come from? */

void install_sigill_handler(void);
void trap_all_mappings(void);
void trap_one_executable_region(unsigned char *begin, unsigned char *end, const char *filename,
	_Bool is_writable, _Bool is_readable);
void trap_one_instruction_range(unsigned char *begin, unsigned char *end, 
	_Bool is_writable, _Bool is_readable);
void walk_instructions(unsigned char *pos, unsigned char *end,
	void (*cb)(unsigned char *pos, unsigned len, void *arg), void *arg);
void replace_instruction_with(unsigned char *pos, unsigned len,
		unsigned char *replacement, unsigned replacement_len);
void replace_syscall_with_ud2(unsigned char *pos, unsigned len);

/* really funky clients, e.g. a ld.so, might not run their own constructor, so ... */
void __libsystrap_force_init(void) __attribute__((visibility("hidden")));

struct ibcs_sigframe; /* opaque */

struct generic_syscall {
	struct ibcs_sigframe *saved_context;
	int syscall_number;
	long int args[6];
};

typedef void post_handler(struct generic_syscall *s, long int ret);
typedef void /*(__attribute__((noreturn))*/ syscall_replacement/*)*/(
	struct generic_syscall *s, 
	post_handler *post
);

extern syscall_replacement *replaced_syscalls[SYSCALL_MAX];

#endif
