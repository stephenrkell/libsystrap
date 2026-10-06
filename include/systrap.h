#ifndef SYSTRAP_H_
#define SYSTRAP_H_

#include <elf.h>
#include <link.h>
#include "systrap-asm.h"

void install_sigill_handler(void);
void trap_all_mappings(void);
void create_fake_vdso(ElfW(auxv_t) *auxv);
typedef int set_trap_fn_t(unsigned char *addr, unsigned len, void *arg);
int set_default_trap(unsigned char *addr, unsigned len, void *arg);
void trap_one_executable_region(unsigned char *begin, unsigned char *end, const char *filename,
	_Bool is_writable, _Bool is_readable, _Bool preserve_exec, set_trap_fn_t *set_trap, void *set_trap_arg);
void trap_one_instruction_range(unsigned char *begin, unsigned char *end,
	_Bool is_writable, _Bool is_readable, _Bool preserve_exec, set_trap_fn_t *set_trap, void *set_trap_arg);
void trap_one_executable_region_given_shdrs(unsigned char *begin,
	unsigned char *end, const char *filename,
	_Bool is_writable, _Bool is_readable, _Bool preserve_exec,
	ElfW(Shdr) *shdrs, unsigned nshdr, ElfW(Addr) laddr, set_trap_fn_t *set_trap, void *set_trap_arg);
_Bool addr_is_in_ld_so(const void *pos);
void walk_instructions(unsigned char *pos, unsigned char *end,
	void (*cb)(unsigned char *pos, unsigned len, void *arg), void *arg);
void replace_instruction_with(unsigned char *pos, unsigned len,
		unsigned char const *replacement, unsigned replacement_len);
void replace_syscall_with_ud2(unsigned char *pos, unsigned len);

/* really funky clients, e.g. a ld.so, might not run their own constructor, so ... */
void __libsystrap_force_init(void) __attribute__((visibility("hidden")));

struct ibcs_sigframe; /* opaque */

#define LCALL_LOG_NRETADDRS 12
extern uintptr_t __systrap_lcall_retaddrs[1ul << LCALL_LOG_NRETADDRS]; /* 32kB -- quite a lot of memory? HMM, it's OK. */

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
	void *site;
	int syscall_number;
	long int args[6];
};

typedef void post_handler(struct generic_syscall *s, long int ret, _Bool do_sigframe_resume);
typedef long /*(__attribute__((noreturn))*/ syscall_replacement/*)*/(
	struct generic_syscall *s
);

extern syscall_replacement *replaced_syscalls[SYSCALL_MAX];

extern void __systrap_call_handler(); /* defined in assembly code */
extern void (*__systrap_pre_handling)()  __attribute__((visibility("protected")));;
extern void (*__systrap_post_handling)()  __attribute__((visibility("protected")));;

/* Macros wrap a C function s.t. it can be called straight
 * from the assembly layer. That means two orthogonal wrappers:
 * - raw to generic_syscall argument signature
 * - saving/restoring all extended registers.
 * How do we do the wrapping?
 * We could output some top-level assembly before and after the
 * wrapped function, and assume that the
 * compiler will output code in order, but that is not a sound
 * assumption. AHA. Under GCC, -fno-toplevel-reorder will 
 * We probably have to make the wrapper create prologues and epilogues
 * surrounded by jumps. */

/* We have to make a call, because the wrappee will 'ret' rather
 * than fall through... so it needs a return address. So clever stuff
 * involving -fno-toplevel-reorder is not needed
 */

/* What does 'raw' mean?
 * It means a thing we can call
 * where
 * the register file matches a syscall site except for rcx (the site) and r11 (clobbered)
 * and the stack pointer which is 8 below the syscall site's (on-stack return address) */

// _Pragma("GCC optimize(\"-fno-toplevel-reorder\")") \

// #define WRAP_FXSAVE(fnname) \

#ifdef __x86_64__
#define WRAP_GENERIC_AS_RAW(generic_fnname) \
extern long __raw_ ## generic_fnname (); \
__asm__(".globl __raw_" #generic_fnname "\n\
__raw_" #generic_fnname ":\n\
    # Save what a SystemV call will clobber and which is not saved in a generic_syscall? \n\
    # On a raw syscall path, this is not necessary. WHAT DOES THIS MEAN? It means \n\
    # the system calling path itself does not need to preserve these, so if we do this \n\
    # it's because our own code, in the call handler, wants us to. We could instead \n\
    # write *that* code to save them itself. Which of these do we want to be the 'raw' \n\
    # calling convention? Answer: the more minimal one. So don't do it! \n\
    # \n\
    # We need a spare System V callee-save register, so use %r12. \n\
    push %r12 \n\
    # Now build a struct generic_syscall right here on the stack. context ptr is null.\n\
    # ibcs_sigframe *context\n\
    # void *site;\n\
    # int syscall_number;\n\
    # long int args[6];\n\
    push %r9     # args[5]\n\
    push %r8     # args[4]\n\
    push %r10    # args[3]\n\
    push %rdx    # args[2]\n\
    push %rsi    # args[1]\n\
    push %rdi    # args[0]\n\
    push %rax    # syscall_number\n\
    push %rcx    # site\n\
    push $0      # signal context is null\n\
    # Of the main general-purpose x86-64 registers, we've now \n\
    # pushed all those that are callee-save in the syscall ABI \n\
    # and not also callee-save in the System V ABI. \n\
    # So it's OK if the code we jump to next trashes them, as long \n\
    # as we come back here and restore them. \n\
    # BUT \n\
    # The code we jump to next is not arbitrary SysV: we have not\n\
    # saved the floating-point or SSE or AVX registers. \n\
    # But it should be programmable in C with the right pragmas\n\
    # and options for disabling those extensions. \n\
    mov %rsp, %rdi \n\
    # Now the regs we saved above are usable as scratch... we will \n\
    # restore them. Don't use others, even %r12! We need to preserve \n\
    # our caller's value of it. \n\
    # Since a post action wants to know the return value of the syscall that happened, \n\
    # and the raw convention puts that in %r11 (see call-handler.S), copy %r11 into %rsi. \n\
    mov %r11, %rsi \n\
    # Now we're ready to do the call, modulo stack-alignment. We need to remember\n\
    # the amount we pad the stack by, using our callee-save register. \n\
    mov %rsp, %r12    \n\
    and $0xf, %r12    # ... since %rbp is our only available SysV-callee-saved register! \n\
    sub %r12, %rsp    # align stack to 16 bytes \n\
    # BUT WAIT -- the generic syscall needs to know the original %rsp somehow \n\
    # when it is to implement clone(). Maybe it needs to go in the args? \n\
    # since sigreturn and clone are essentially using %rsp as an arg. \n\
    callq " #generic_fnname " \n\
    add %r12, %rsp    # undo stack alignment \n\
    add $8, %rsp      # pop the zero ('context') \n\
    pop %rcx          # pop the real %rcx ('site') \n\
    add $8, %rsp      # no longer syscall_number; %rax has the return value, so leave it there \n\
    pop %rdi \n\
    pop %rsi \n\
    pop %rdx \n\
    pop %r10 \n\
    pop %r8 \n\
    pop %r9 \n\
    pop %r12  # the callee-save register we freed up for ourselves above \n\
    ret \n\
")
/* NOTE: we don't save/restore %rax, %rcx, %r11. See comment above.*/
#else
#define WRAP_GENERIC_AS_RAW(generic_fnname)   /* FIXME: i386 version */
#endif /* __x86_64__ */

#ifdef __x86_64__
#define WRAP_IN_FXSAVE(extusing_fnname) \
extern long __withfxsave_ ## extusing_fnname (); \
__asm__(".globl __withfxsave_" #extusing_fnname "\n\
__withfxsave_" #extusing_fnname ":\n\
	# We are to be callable from a raw-ABI caller, so we can't assume more than 8-byte \n\
	# stack alignment. And as usual, only %r11 is clobberable. %rcx holds the syscall site. \n\
	push %rbp \n\
	mov %rsp, %rbp \n\
	sub $512, %rsp \n\
	and $~15, %rsp \n\
	fxsave (%rsp)\n\
	# What can we assume about our wrapped callee? It need not be SysV. But if it is, that's OK \n\
	# in that our stack has the correct alignment. Will it preserve %r11? No. But if it's SysV, \n\
	# it does not conform to the raw ABI because it doesn't preserve a bunch of registers. So \n\
	# I think we should assume that our callee is raw. The only SysV interface we care about is \n\
	# the generic one; we define no 6-arg raw SysV ABI, for example (just use real raw!). I suppose \n\
	# we might want such an ABI in future. If we did that, we'd want a WRAP_6ARGSYSV_AS_RAW above. \n\
	callq " #extusing_fnname " \n\
	fxrstor (%rsp) \n\
	mov %rbp, %rsp \n\
	pop %rbp \n\
	retq \
")
#else
#define WRAP_IN_FXSAVE(extusing_fnname)   /* FIXME: i386 version */
#endif /* __x86_64__ */

#define MAX_VPERM_RANGES 128
#if 0
struct vperm_range
{
	volatile _Atomic void *addr;
	size_t length;
	int prot;
};
#endif
struct vperm_range
{
	unsigned char      perms:2;      // interpretation is private to vperm.c
	unsigned short     npages:14;
#if defined(__x86_64__)
	unsigned long long addr:48;      // could spare one more bit here, but check for bad perf (TODO)
#elif defined(__i386__)
	unsigned long addr; // FIXME: padding / field ordering is messed-up here on i386
#else
#error "Unsupported architecture"
#endif
};
#define VPERM_NPAGES_MAX ((1ul<<14) - 1)
extern struct vperm_range
vperm_ranges[MAX_VPERM_RANGES] __attribute__((visibility("hidden")));
extern unsigned vperm_ranges_nused __attribute__((visibility("hidden")));
struct vperm_range *add_vperm_range(void *addr, size_t len, int prot) __attribute__((visibility("hidden")));
struct vperm_range *find_vperm_range(void *addr) __attribute__((visibility("hidden")));
struct vperm_range *find_first_vperm_range_in(void *begin, void *end) __attribute__((visibility("hidden")));
int compare_vperm_ranges(const void *m1_as_void, const void *m2_as_void) __attribute__((visibility("hidden")));
void replace_vperms_over(void *begin, void *end, int prot) __attribute__((visibility("hidden")));
//enum vperm_perms vperms_from_prot(int prot) __attribute__((visibility("hidden")));
int prot_from_vperms(int perms) __attribute__((visibility("hidden")));
typedef int vperm_action_cb(struct vperm_range *r, void *arg);
enum vperm_range_action
{
	VPERM_A_NOTHING,
	VPERM_A_DELETE
};
int with_vperm_range_exclusive(void *addr, vperm_action_cb *cb, void *cb_arg) __attribute__((visibility("hidden")));
int with_vperm_range_ro(void *addr, vperm_action_cb *cb, void *cb_arg) __attribute__((visibility("hidden")));

#endif
