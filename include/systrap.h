#ifndef SYSTRAP_H_
#define SYSTRAP_H_

#include <elf.h>
#include <link.h>

#define SYSCALL_MAX 1023 /* A safe-ish overapproximation for now... */

void install_sigill_handler(void);
void trap_all_mappings(void);
void create_fake_vdso(ElfW(auxv_t) *auxv);
void trap_one_executable_region(unsigned char *begin, unsigned char *end, const char *filename,
	_Bool is_writable, _Bool is_readable, _Bool preserve_exec);
void trap_one_instruction_range(unsigned char *begin, unsigned char *end,
	_Bool is_writable, _Bool is_readable, _Bool preserve_exec);
void trap_one_executable_region_given_shdrs(unsigned char *begin,
	unsigned char *end, const char *filename,
	_Bool is_writable, _Bool is_readable, _Bool preserve_exec,
	ElfW(Shdr) *shdrs, unsigned nshdr, ElfW(Addr) laddr);
_Bool addr_is_in_ld_so(const void *pos);
void walk_instructions(unsigned char *pos, unsigned char *end,
	void (*cb)(unsigned char *pos, unsigned len, void *arg), void *arg);
void replace_instruction_with(unsigned char *pos, unsigned len,
		unsigned char const *replacement, unsigned replacement_len);
void replace_syscall_with_ud2(unsigned char *pos, unsigned len);

/* really funky clients, e.g. a ld.so, might not run their own constructor, so ... */
void __libsystrap_force_init(void) __attribute__((visibility("hidden")));

struct ibcs_sigframe; /* opaque */

/* If we give the application a fake vDSO / sysinfo,
 * we have to save/restore the original. */
extern void *real_sysinfo;
#ifdef __i386__
/* We snarf the offset from fake_sysinfo's __kernel_vsyscall
 * to the int80 instruction that follows sysenter. */
extern unsigned sysinfo_int80_offset;
extern unsigned sysinfo_sysenter_offset;
#define KERNEL_VSYSCALL_MAX_SIZE 32
#endif
extern void *fake_sysinfo;

struct generic_syscall {
	struct ibcs_sigframe *saved_context;
	int syscall_number;
	long int args[6];
};

typedef void post_handler(struct generic_syscall *s, long int ret, _Bool do_sigframe_resume);
typedef void /*(__attribute__((noreturn))*/ syscall_replacement/*)*/(
	struct generic_syscall *s,
	post_handler *post
);

extern syscall_replacement *replaced_syscalls[SYSCALL_MAX];

void __systrap_pre_handling(struct generic_syscall *gsp);
void __systrap_post_handling(struct generic_syscall *gsp, long int ret, _Bool do_sigframe_resume);
void __libsystrap_noop_post_handling(struct generic_syscall *gsp, long int ret, _Bool do_sigframe_resume);

#endif
