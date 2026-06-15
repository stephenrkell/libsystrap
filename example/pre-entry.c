#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include "raw-syscalls-defs.h"
#include "raw-syscalls-asm.h"
#include "raw-syscalls-impl.h"

#include <link.h>
#include <err.h>
#include <dlfcn.h>
#include <assert.h>
#include "systrap.h"
#include "relf.h"
#include "trace-syscalls.h"
#include "dso-meta.h" /* for bsearch_leq_generic */

#include <asm/ldt.h>
#include <unistd.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <sys/mman.h>
#include <linux/memfd.h>
#include <string.h> /* for memcpy */

static void print_ldt(unsigned nentries)
{
	/* XXX: weirdly, Linux's modify_ldt read operation (func==0) reads raw LDT
	 * descriptors... this def is from arch/x86/include/asm/desc_defs.h
	 * and the smoking guns are in 
	 * arch/x86/include/asm/mmu.h (mm_context_t has 'ldt' pointer to a struct ldt_struct)
	 * arch/x86/include/asm/mmu_context.h (ldt_struct has an 'entries' pointer to array of struct desc_struct
	 * arch/x86/kernel/ldt.c has read_ldt() doing a copy_to_user of mm->context.ldt->entries
	 *
	 * BUT note also that "system descriptors in IA-32e mode are 16 bytes instead of 8 bytes."
	 * (see Intel manual linked below)
	 */
	/* 8 byte segment descriptor */
	struct desc_struct {
		uint16_t	limit0;
		uint16_t	base0;
		uint16_t	base1: 8, type: 4, s: 1, dpl: 2, p: 1;
		uint16_t	limit1: 4, avl: 1, l: 1, d: 1, g: 1, base2: 8;
	} __attribute__((packed));

	struct desc_struct buf[nentries];
	size_t bufsz = sizeof (struct desc_struct) * nentries;
	long nread = //modify_ldt(0, buf, sizeof buf);
			syscall(SYS_modify_ldt, /* read */ 0x0, buf, (unsigned long) bufsz);
	if (nread != bufsz) { warnx("modify_ldt failed to read %ld bytes (read only %ld)", (unsigned long) bufsz, (long) nread); }
	for (unsigned i = 0; i < nread / sizeof (struct desc_struct); ++i)
	{
		warnx("desc 0x% 4x has base0=%04x base1=%04x base2=%02x limit0=%04x limit1=%x "
			  "type=%x s=%x dpl=%x p=%x avl=%x l=%x d=%x g=%x",
			   i, (unsigned) buf[i].base0, (unsigned) buf[i].base1, (unsigned) buf[i].base2,
			   (unsigned) buf[i].limit0, (unsigned) buf[i].limit1,
			   (unsigned) buf[i].type, (unsigned) buf[i].s, (unsigned) buf[i].dpl,
			   (unsigned) buf[i].p, (unsigned) buf[i].avl, (unsigned) buf[i].l, (unsigned) buf[i].d,
			   (unsigned) buf[i].g);
	}
}

/* We have just received control from a special unique trampoline placed
 * at 0x1f1f1f1f. The stack and register state should be identical to a normal
 * call made at the site of a syscall, except that the return address is a
 * segment/offset pair that has discarded the upper 32 bits of the call site
 * (and an ordinary functional prologue has just occurred, possibly pushing
 * %rbp and saving %rsp into it). We are in 64-bit mode.
 *
 * What to do about the upper 32 bits? One idea that works for %rip-relative
 * puns (near the code) is to issue a selection of LDT entries from among
 * {0707,0f0f,1717,1f1f,2727,2f2f, ...} -- 32 entries in total. Each of these
 * can have its own trampoline that restores a corresponding top-bits pattern.
 * That may be overkill, however, and only works for %rip-relative puns.
 *
 * Also it doesn't work for %rax-relative or %rbp-relative puns. Falling back
 * on uniqueness may be the best thing here: keep the trap sites in a sorted
 * array and bsearch on them. */
__attribute__((visibility("hidden")))
uintptr_t fixup_return_address_to_trap_site(uintptr_t addr)
{
#define proj_trap_addr(p) (uint32_t)((p)->addr)
	struct trap_site *found = bsearch_leq_generic(struct trap_site, (uint32_t) addr - 6,
		__trap_sites, __next_trap_site, proj_trap_addr);
	if (found) return found->addr; // 64-bit address
	return addr;
}
/* The stuff below works(-ish), but it is complex. It'd be nice if we could:
 * - get the upper bits from the LDT entry number used
 *      -- but GAH, only works for %rip-relative puns!
 *      -- we could use the LBR? gah, but it is privileged (rdmsr)
 *                https://sorami-chi.hateblo.jp/entry/2017/12/17/230000
 *           -- a kernel driver might help us...
 * - avoid helper call => work with caller's stack alignment
 * - refactor handle_sigill s.t. we don't have to do the fake frame thing
 * - exploit that %rcx and %r11 are scratch at the site of a syscall
 */

#define RAX_SLOT 152 /* uc(8) + uc_mcontext (40) + 104(rax) */
#define RIP_SLOT 176
#define RBP_SLOT 128
#define RSP_SLOT 168
#define RDI_SLOT 112
#define RSI_SLOT 120
#define RDX_SLOT 144
#define R10_SLOT 64
#define R8_SLOT  48
#define R9_SLOT  56
_Static_assert(RAX_SLOT == offsetof(struct ibcs_sigframe, uc.uc_mcontext.rax), "offset of rax");
#define PRETCODE_SLOT 0
#define STRUCTURE_SIZE 448
_Static_assert(STRUCTURE_SIZE >= sizeof (struct ibcs_sigframe), "size of sigframe structure");
_Static_assert(STRUCTURE_SIZE % 16 == 0, "size of sigframe structure as a multiple of 16");
__asm__(".text \n\
	.globl syscall_lcall_handler               \n\
	syscall_lcall_handler:                     \n\
	  # %rax is scratch... it's what got us here (jmpq *(%rax)) but we don't need it. \n\
	  # The return address is on the stack where it was pushed by the lcall at the trap site. \n\
	  # The syscall number is on the stack *after* (below) the return address. \n\
	  # If we return via pretcode we will need to restore the stack pointer and other \n\
	  # clobbered registers ourselves... handle_sigill wants to pull the generic syscall \n\
	  # straight out of the frame. We can set ourselves as the return address (pretcode), \n\
	  # which would normally point to a sigreturn trampoline. \n\
	  # \n\
	  # First get us to 8-modulo-16 alignment, which we will require for jumping to handle_sigill.\n\
	  # We must allocate our fake signal frame at that alignment. \n\
	  # Assume we might be invoked at either 8-modulo-16 or 0-modulo-16 alignment (CHECK?). \n\
	  mov %rsp, %rax                                                                 \n\
	  and $0xf, %rax                                                                 \n\
	  and $-0x10, %rsp       # now %rsp is 0-modulo-16 and the delta is in %rax \n\
	  push %rax              # push the delta. Now we are 8-modulo-16. Q: WHERE do we pop this? \n\
	  sub $"stringifx(STRUCTURE_SIZE)", %rsp  # size rounded up from struct ibcs_sigframe, multiple of 16 => alignment unchanged at 8-modulo-16 \n\
	  lea (8+"stringifx(STRUCTURE_SIZE)")(%rsp,%rax,1), %rax  # Now %rax has the on-stack address of our caller-pushed %rax \n\
	  mov 0(%rax), %rax           # Now %rax has the caller-pushed syscall number \n\
	  mov %rax, "stringifx(RAX_SLOT)"(%rsp)  # the syscall number \n\
	  # Now we are at 8-modulo-16 and the round-down amount is at STRUCTURE_SIZE(%rsp) \n\
	  mov "stringifx(STRUCTURE_SIZE)"(%rsp), %rax         # Get the stack adjustment amount \n\
	  pushq %rdi                  # Push an *odd* number of things; we need to reach 0-modulo-16 \n\
	  mov (24+"stringifx(STRUCTURE_SIZE)")(%rsp,%rax,1), %rdi  # Get the 64-bit long return address into %rax (skip over the syscall num!) \n\
	  lea (24+"stringifx(STRUCTURE_SIZE)")(%rsp,%rax,1), %rax  # Interlude: put the *address* of the ret addr slot into %rax \n\
	  cltq                        # Chop the top half and sign-extend \n\
	  pushq %rcx                  \n\
	  pushq %rdx                  \n\
	  pushq %rsi                  \n\
	  pushq %r8                   \n\
	  pushq %r9                   \n\
	  pushq %r10                  \n\
	  pushq %r11                  \n\
	  pushq %rax \n\
	  # Now we are 0-modulo-16 so OK to call \n\
	  callq fixup_return_address_to_trap_site \n\
	  # Immediately put the return value in %rdi, so we can restore %rax \n\
	  mov %rax, %rdi \n\
	  popq %rax                  \n\
	  # Now %rax once again holds the address of the on-stack return address slot \n\
	  popq %r11                  \n\
	  popq %r10                  \n\
	  popq %r9                  \n\
	  popq %r8                  \n\
	  popq %rsi                  \n\
	  popq %rdx                  \n\
	  popq %rcx                  \n\
	  # Now we are *almost* back to our home 8-modulo-16 position, for the jump to handle_sigill! \n\
	  # But the call's return value is in %rdi as we restored %rax\n\
	  # ... which was holding the address of the return address slot. Use it! \n\
	  # WHY is this OK? It's because we don't 'lret' to return from the lcall... see bottom. \n\
	  mov %rdi,(%rax)            \n\
	  # Now we can put the fixed-up return address back in %rax and restore %rdi\n\
	  mov %rdi, %rax             \n\
	  popq %rdi \n\
	  # Now we are *really* back to our home 8-modulo-16 position \n\
	  mov %rax, "stringifx(RIP_SLOT)"(%rsp)      # the return address goes in %rip's slot  \n\
	  lea 1f(%rip), %rax                         # So that we get control back after 'jmp'... \n\
	  mov %rax, "stringifx(PRETCODE_SLOT)"(%rsp) # ... our successor insns' address goes in pretcode \n\
	  mov %rbp, "stringifx(RBP_SLOT)"(%rsp)      # \n\
	  # Take care to fix up %rsp... current is 8(retaddr)+8(syscallnum)+8(delta)+padding+448 bytes lower than at the trap! \n\
	  mov "stringifx(STRUCTURE_SIZE)"(%rsp), %rax   # get padding amount in %rax \n\
	  lea (24+"stringifx(STRUCTURE_SIZE)")(%rsp,%rax,1), %rax  # Now %rax has the on-stack address of our caller-pushed syscall num \n\
	  mov %rax, "stringifx(RSP_SLOT)"(%rsp)      # \n\
	  mov %rdi, "stringifx(RDI_SLOT)"(%rsp)      # \n\
	  mov %rsi, "stringifx(RSI_SLOT)"(%rsp)      # \n\
	  mov %rdx, "stringifx(RDX_SLOT)"(%rsp)      # \n\
	  mov %r10, "stringifx(R10_SLOT)"(%rsp)      # \n\
	  mov %r8,  "stringifx(R8_SLOT)"(%rsp)       # \n\
	  mov %r9,  "stringifx(R9_SLOT)"(%rsp)       # \n\
	  # The registers we need to have saved into our fake frame here are the union of \n\
	  # those needed by the syscall and those we want to save across handle_sigill \n\
	  # We are still 8-modulo-16 so OK to jump... \n\
	  jmp handle_sigill  # avoids the sigreturn path... uses pretcode! \n\
	  # %rax remains scratch because handle_sigill returns nothing (except in RAX_SLOT)... \n\
	1:pushq $0           # 'ret' popped the return addr, so push null pretcode back on the stack \n\
	  # Now we are back to our home 8-modulo-16 position \n\
	  mov "stringifx(RBP_SLOT)"(%rsp), %rbp # \n\
	  mov "stringifx(RDI_SLOT)"(%rsp), %rdi # \n\
	  mov "stringifx(RSI_SLOT)"(%rsp), %rsi # \n\
	  mov "stringifx(RDX_SLOT)"(%rsp), %rdx # \n\
	  mov "stringifx(R10_SLOT)"(%rsp), %r10 # \n\
	  mov "stringifx(R8_SLOT)"(%rsp), %r8 # \n\
	  mov "stringifx(R9_SLOT)"(%rsp), %r9 # ... *almost* finished with the fake signal frame \n\
	  # \n\
	  add $"stringifx(STRUCTURE_SIZE)", %rsp  # deallocate most of our struct bytes... all but the round-down amount \n\
	  # We need to get the %rip and %rax out of the fake signal frame. \n\
	  # 1. Get the fixed-up %rip in %rax \n\
	  mov ("stringifx(RIP_SLOT)"-"stringifx(STRUCTURE_SIZE)")(%rsp), %rax \n\
	  # 2. Undo the stack adjustment. The adjustment *amount* is still stored on the stack \n\
	  # ... i.e. we are still 8 bytes lower than when we did the original adjustment. \n\
	  # Note we are doing this in a different order: we down-adjusted then pushed the delta, \n\
	  # but here we are up-adjusting before we pop the delta slot. \n\
	  add 0(%rsp), %rsp    # up-adjust using the delta we stored \n\
	  add $8, %rsp         # we pushed the delta, so pop that (or the padding) \n\
	  # 3. Save the fixed-up %rsp into the return address slot. \n\
	  # The lcall return address was in %rsp+8 on entry and we have now restored %rsp. \n\
	  movq %rax, 8(%rsp)  \n\
	  # 4. Fish out the %rax by re-calculating the stack padding amount we used \n\
	  mov %rsp, %rax\n\
	  and $0xf, %rax \n\
	  neg %rax\n\
	  mov ("stringifx(RAX_SLOT)"-"stringifx(STRUCTURE_SIZE)"-8)(%rsp,%rax,1), %rax \n\
	  add $8, %rsp # pop off the syscall number pushed by our caller \n\
	  # we use a plain 'ret' to return from the lcall (!) -- it will pop the return addr \n\
	  retq \n\
	  "
);
/* How are sigreturn and clone expected to work along the lcall path?
 * Sigreturn currently works... how? From do-syscall.h:
         * To do a sigreturn, we simply restore the user's stack pointer
         * to what it was at the site of the trap... i.e. do the same sigreturn
         * that the original code was trying to do, just from a different code address.
 * So, perhaps step 1 is to ensure that the in-frame %rsp is accurate.
 */
extern void syscall_lcall_handler(void);
#if 0
void syscall_lcall(void)
{
	struct ibcs_sigframe fake_frame = (struct ibcs_sigframe) {
		/* char * */ .pretcode = fixup_return_address(__builtin_return_address(0) - 2),
#ifdef __i386__
		/* int*/ .sig = ; // on x86 sigill is not RT, so we get a non-rt sigframe
#endif
#ifdef __i386__
		/* struct {
			struct sigcontext uc_mcontext;
		} */ .uc = { .uc_mcontext = (struct sigcontext) { } },
#else
		/* struct __asm_ucontext */ .uc = (struct __asm_ucontext) {
			/* unsigned long */ // .uc_flags =
			/* struct ucontext  * */ //.uc_link =
			/* stack_t */           // .uc_stack =
			/* struct sigcontext */ .uc_mcontext = (struct sigcontext) {
#define GET_REG(frag) \
    (( })
				 /* uint64_t */ .r8 = GET_REG(r8),
				 /* uint64_t */ .r9 = GET_REG(r9),
				 /* uint64_t */ .r10 = GET_REG(r10),
				 /* uint64_t */ .r11 = GET_REG(r11),
				 /* uint64_t */ .r12 = GET_REG(r12),
				 /* uint64_t */ .r13 = GET_REG(r13),
				 /* uint64_t */ .r14 = GET_REG(r14),
				 /* uint64_t */ .r15 = GET_REG(r15),
				 /* uint64_t */ .rdi = GET_REG(rdi),
				 /* uint64_t */ .rsi = GET_REG(rsi),
				 /* uint64_t */ .rbp = GET_REG(rbp),
				 /* uint64_t */ .rbx = GET_REG(rbx),
				 /* uint64_t */ .rdx = GET_REG(rdx),
				 /* uint64_t */ .rax = GET_REG(rax),
				 /* uint64_t */ .rcx = GET_REG(rcx),
				 /* uint64_t */ .rsp = GET_REG(rsp),
				 /* uint64_t */ .rip = GET_REG(rip),
			}/ ,
			/* sigset_t */        // uc_sigmask;   /* mask last for extensibility */
		},
#endif
		struct __asm_siginfo info = (struct __asm_siginfo) { }; // FIXME: this is wrong on i386

	};
	__asm__ volatile ("mov %0, %%rsp\n\
	                   jmp handle_sigill\n" : : "r"(&fake_frame));
}
#endif /* 0 */

void map_selector_pages(void)
{
	int the_fd = memfd_create("selector", MFD_CLOEXEC/*|MFD_HUGETLB*//*|MFD_HUGE_2MB*/);
	if (the_fd == -1) warn("memfd_create failed", __errno_location());
	assert(the_fd != -1);
	/* do it in superpages (TODO: restore this / figure out why HUGETLB doesn't work) */
#define SELECTOR_MAPPING_UNIT 2097152
	int ret = ftruncate(the_fd, SELECTOR_MAPPING_UNIT);
	if (ret != 0) warnx("ftruncate said errno %d", __errno_location());
	ssize_t written = 0;
	short unsigned dummy;
	ssize_t nread = read(the_fd, &dummy, 2);
	assert(nread == 2); // reading works OK
	off_t seekset = lseek(the_fd, 0, SEEK_SET);
	assert(seekset == 0);
	static char selbuf[2048];
	wmemset((wchar_t *) selbuf, (wchar_t) 0x1f1f1f1fu, sizeof selbuf / sizeof (wchar_t));
	for (unsigned n = 0; n < SELECTOR_MAPPING_UNIT / sizeof selbuf; ++n)
	{
		written = write(the_fd, &selbuf[0], sizeof selbuf);
		assert(written == sizeof selbuf);
	}
	/* HMM. We assume we can just trample over the whole first 4GB. HACK!
	 * If we kept a bitmap of which pages we'd trampled on, it would have
	 * 2^20 bits or 2^17 bytes or 128kB, which is manageable. */
	for (unsigned long long spagenum = 1; spagenum < 1ull<<11; ++spagenum)
	{
		void *addr = (void*)(spagenum << 21);
		//warnx("asking for a mapping at %p", addr);
		void *ret = raw_mmap(addr, SELECTOR_MAPPING_UNIT,
				PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED/*|MAP_HUGETLB|MAP_HUGE_2MB*/, the_fd, 0);
		if (!(ret == (void*)(spagenum << 21))) warnx("mmap said %p cf addr %p", ret, addr);
		assert(ret == (void*)(spagenum << 21));
	}
	close(the_fd);
	/* Now put something at the address 0x1f1f1f1f.
	 * What does it need to do?
	 * Try:
	 * (1) a far jump to the next instruction via __USER_CS, getting us back into 64-bit mode;
	 *        while there is no absolute direct lcall in 64-bit mode,
	 *        we are now in 32-bit mode!
	 * (2) jump to a trampoline that mimics a signal frame
	 *     (easiest to do the jump via a function pointer whose bytes are inline),
			  GAH-- but we need a scratch register for this!!11
			  we can push but we can't restore before our handler...
			  popping %rax there may be the best option sadly
	 *     in among which...
	 * (3) something about retrieving our return address -- we only have 32 bits of it?!?!
	 *     Probably we only work if our trap site is uniquely identified by its low 32 bits.
	 *     Is there something dirty we can do to guess? Not really.
	 *     Just bsearch in a table of trap sites' lower 32.
	 * (4) call our generic syscall replacement but don't let it sigreturn for us
	 * (4) On the return path, do a *non*-long ret after fixing up the stack
	 *     (or we could fix up the stack first thing? fixup is easy because
	 *     it's only one 64-bit word on the stack)
	 * */
	static const char the_asm[] = {
#if 0 /* REAL version */
	/* 1f: */ 0xea, 0x26, 0x1f, 0x1f, 0x1f, 0x33, 0x00, /* ljmp   $0x33,$0x1f1f1f26 */
	                                                    /* now we are 64-bit again */
	/* 26: */ 0x50,                                     /* push rax */
	/* 27: */ 0x48, 0x8b, 0x05, 0x02, 0x00, 0x00, 0x00, /* mov 0x2(%rip), %rax */ // <-- relative to *next* insn %rip
	/* 2e: */ 0xff, 0x20,                               /* jmpq *%rax */
	/* 30: */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  /* placeholder for address of handler */
	}; /* FIXME: don't put the function-pointer placeholder in executable memory -- just
	    * use a static global var? no because we are going to memcpy it.
	    * Even if we use movabs, the raw bytes will go in executable memory. */
#else /* TESting stuff version */
	/* 1f: */ 0xea, 0x26, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, /* ljmp $0x1f1f,$0x1f1f1f26 */
			/* WHEN I add this same-segment lcall/ljmp, I get a SIGILL at 0x1f1f1f26!
			 * That is interesting...
			 * the lcall apparently succeeds and
			 * we should still be in 32-bit mode. So why the sigill? AH... we were jumping
			 * back to it from our ljump below. */
			  0x90, // <--26
			  0x90,
			  0x90,
			  0x90, //0x31, // clear eax/rax
			  0x90, // 0xc0,
			  0x90, //0x48, // 32-bit detection sequence
			  0x90, // 0x85,
			  0x90, //0xc0,
			  0x90,
	/* 2f: */ 0xea, 0x36, 0x1f, 0x1f, 0x1f, 0x33, 0x00, /* ljmp   $0x33,$0x1f1f1f2d */
	                                                    /* now we are 64-bit again */
	/* 36: */ 0x50,                                     /* push rax */
	/* 37: */ 0x48, 0x8b, 0x05, 0x02, 0x00, 0x00, 0x00, /* mov 0x2(%rip), %rax */ // <-- relative to *next* insn %rip
	/* 3e: */ 0xff, 0xe0,                               /* jmp *%rax */
	/* 40: */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  /* placeholder for address of handler */
};
#endif
	mprotect((void*) 0x1f1f1000, 4096, PROT_READ|PROT_WRITE);
	memcpy((void*) 0x1f1f1f1f, the_asm, sizeof the_asm - 8);
	void *tgt = syscall_lcall_handler;
	memcpy((char*) 0x1f1f1f1f + sizeof the_asm - 8, &tgt, 8);
	mprotect((void*) 0x1f1f1000, 4096, PROT_READ|PROT_EXEC);
}
void install_descriptor(void)
{
	print_ldt(8192);
#if 0
	       The user_desc structure is defined in <asm/ldt.h> as:

           struct user_desc {
               unsigned int  entry_number;
               unsigned int  base_addr;
               unsigned int  limit;
               unsigned int  seg_32bit:1;
               unsigned int  contents:2;
               unsigned int  read_exec_only:1;
               unsigned int  limit_in_pages:1;
               unsigned int  seg_not_present:1;
               unsigned int  useable:1;
           };
#endif
	/* %cs is normally 0x33, i.e. 0b00110011 meaning ring 3, GDT, segment 5 (0b110) */
	struct user_desc desc = {
		.entry_number = 0x3e3, /* 1f 1f -> segment entry is 0b 0001 1111 0001 1 111 <- LDT, DPL 3
		                                                         0011 1110 0011
		/* Now the contents... */
		/* see https://cdrdv2-public.intel.com/843856/253668-sdm-vol-3a-dec-24.pdf */
		.base_addr = 0x0000 ,
		.limit = 0xfffff /* limit has only 20 bits */,
		.seg_32bit = 1, /* sets 'd' flag in LDT entry: 'default operation size' (0==16b, 1==32b) */
		.contents /* a.k.a. segment type */ = /* sets top 2 bits of 'type' field */ /*MODIFY_LDT_CONTENTS_CODE*/ 2,
				/* the type field is four bytes whose meaning is different for code/data/system,
				 * but for code/data, the bits are:
				 * bit 3: executable (1) or non-executable (0)
				 * bit 2: for executable: "conforming" (1) or non- (0); for non-executable "expand-down" or non- (0)...
				 * bit 1: is "write" (1) (for non-executable) vs non- (0) or "read" (1) (for executable) vs non- (0)
				 * bit 0 is "accessed" (always set by the kernel).
				 * What does "conforming" mean? It's about change of privilege. Linux sets non-conforming always.
				 * This means DPL must match if we are to avoid generating a GP fault. But it does match. */
		.read_exec_only = 0 /* inverted and used to set bit 1 of 'type'; we want readable and executable */,
		.limit_in_pages = 1 /* sets 'g' for 'granularity' bit in entry */,
		.seg_not_present = 0 /* inverted and used to set 'p'; we want it to be present, so 0 */,
		.useable = 1 /* = "available" bit 52 in descriptor?
			means available for software to use / no defined meaning to hardware...
			an "oldmode" write (0x1) via modify_ldt will set this to '0', but
			a  new-mode write (0x11) will not. */,
#if 0
		.lm /* 1-bit undocumented field */ = 1
#endif
	};
	/* The logic to populate the actual LDT entry looks like the following (from Linux 6.1.148,
	 * fill_ldt() in arch/x86/include/asm/desc.h):

		desc->limit0		= info->limit & 0x0ffff;

		desc->base0		= (info->base_addr & 0x0000ffff);
		desc->base1		= (info->base_addr & 0x00ff0000) >> 16;

		desc->type		= (info->read_exec_only ^ 1) << 1;
		desc->type	       |= info->contents << 2;
		// Set the ACCESS bit so it can be mapped RO
		desc->type	       |= 1;

		desc->s			= 1;
		desc->dpl		= 0x3;
		desc->p			= info->seg_not_present ^ 1;
		desc->limit1		= (info->limit & 0xf0000) >> 16;
		desc->avl		= info->useable;
		desc->d			= info->seg_32bit;
		desc->g			= info->limit_in_pages;

		desc->base2		= (info->base_addr & 0xff000000) >> 24;

		// Don't allow setting of the lm bit. It would confuse
		// user_64bit_mode and would get overridden by sysret anyway.
		desc->l			= 0;

	 */

	/*
	   Even on 64-bit kernels, modify_ldt() cannot be used to create a long mode  (i.e.,  64-bit)  code
       segment.   The  undocumented  field "lm" in user_desc is not useful, and, despite its name, does
       not result in a long mode segment.
	 */
	int ret = syscall(SYS_modify_ldt,  0x1 /*0x11*/ /* write  with magic Dosemu extensions just in case useful: 
	 http://www.dosemu.org/docs/README-tech/0.99/README-tech-5.html */, &desc, sizeof desc);

	if (ret != 0) { warnx("modify_ldt failed to write"); return; }
	warnx("modify_ldt() succeeded writing");
	/* Now let's print the LDT for checksies */
	print_ldt(/*0x3e3 + 1*/ 0x3e3 + 1);
		/* XXX: various sources conflict about whether modify_ldt can create call gates.
	 * Dosemu implies yes. http://www.dosemu.org/docs/README-tech/0.99/README-tech-5.html
	   This dates from around the time modify_ldt was created.
	 * ibcs-us says no, but implies that maybe it once worked?
	 * https://ibcs-us.sourceforge.io/README.txt
	 * hxp says no, and relies on an exploit to do a one-byte write that flips a
	 * non-callgate entry into a call gate
	 * https://hxp.io/blog/99/hxp-CTF-2022-one_byte-writeup/
	 * This says no:
	 * https://stackoverflow.com/questions/32648630/add-a-call-gate-descriptor-in-local-descriptor-table-ldt-for-privilege-escalat
	 *
	 * Are all call gates "system"?
	 * OK, trying the fancier solution
	 */
}

extern uintptr_t __start___replaced_syscalls;
extern uintptr_t __stop___replaced_syscalls;

void __real_enter(void *entry_point);
void __wrap_enter(void *entry_point)
{
	// FIXME: libsystrap isn't being init'd, so force it
	__libsystrap_force_init();
	init_fds();
	/* We want to trap only the inferior ld.so's executable phdr(s).
	 * How do we find them?
	 * We could wrap load_one_phdr -- is that good value?
	 * We will need to do some stuff for vdso,
	 * and some stuff for bootstrapping, but that will probably
	 * be different.
	 * Oh.
	 * But we needed librunt to find the section boundaries.
	 * Does it make sense to run librunt in our primordial ld.so environment?
	 * It wants to be able to do struct R_DEBUG_STRUCT_TAG *find_r_debug(void)
	 * Do we want to create a fake _r_debug so that relf.h can work?
	 * Maybe none of librunt works in this environment?
	 * And what about when our signal handler runs? Does it
	 * need to see the "real" link map of the guest program?
	 * The host/guest distinction seems good.
	 *
	 * Can I locate the _r_debug via the DT_DEBUG, as a fallback?
	 * Then as long as *some* _DYNAMIC with a DT_DEBUG can be found,
	 * we have a pointer to the process's unique "real" _r_debug, which
	 * is defined... where? Yes, in the ld.so.
	 */
	install_descriptor();
	trap_all_mappings();
	map_selector_pages();
	install_sigill_handler();
	// FIXME: should go in the real entry point?
#if defined(__i386__)
	if (fake_sysinfo)
	{
		unsigned char *tls;
		__asm__("mov %%gs:0x0,%0" : "=r"(tls));
		*(void**)(tls+16) = fake_sysinfo; // FIXME: need a reference for this please
	}
#endif
	/* Install replacements.
	 * Why not just initialize the replaced_syscalls array itself?
	 * Well, it can't be split across multiple files, unlike this approach.
	 * This is a bit nasty though.
	 */
	unsigned nreplacements = (&__stop___replaced_syscalls - &__start___replaced_syscalls) / 2;
	for (unsigned n = 0; n < nreplacements; ++n)
	{
		uintptr_t syscall_n = (&__start___replaced_syscalls)[2*n];
		assert(syscall_n < SYSCALL_MAX);
		void (*replacement)(struct generic_syscall *s, post_handler *post)
		 = (void*)(&__start___replaced_syscalls)[2*n + 1];
		replaced_syscalls[syscall_n] = replacement;
	}
	find_r_debug()->r_map = NULL;
	/* For the lcall instrumentation, we need to have a low stack.
	 * Since we don't come back here, now is the time to create a new stack
	 * and call the entry point with it.
	 *
	 * HACK: pick a low 8MB, mprotect it writeable, zero it, set rsp, go! 
	 */
#if defined(__x86_64__)
#define LOW_STACK_TOP  0x71000000
#define LOW_STACK_SIZE    8388608
	raw_mprotect((void*)(LOW_STACK_TOP - LOW_STACK_SIZE), LOW_STACK_SIZE, PROT_READ|PROT_WRITE);
	bzero((void*)(LOW_STACK_TOP - LOW_STACK_SIZE), LOW_STACK_SIZE);
	/* __real_enter will reset the stack pointer, so make sure we influence it. */
	extern ElfW(auxv_t) *p_auxv;
	extern void *sp_on_entry;
	struct auxv_limits limits = get_auxv_limits(p_auxv);
	/* We need to memcpy the initial stack, otherwise ld.so won't be able to get
	 * its aux vector and whatnot. */
	size_t memcpy_len = RELF_ROUND_UP_PTR_((uintptr_t) limits.asciiz_end, 16)
		 - (uintptr_t) sp_on_entry;
	void *new_sp_on_entry = (void*) LOW_STACK_TOP - memcpy_len;
	memcpy(new_sp_on_entry, sp_on_entry, memcpy_len);
	debug_printf(0, "low stack: replacing rsp=%p with %p\n", sp_on_entry, new_sp_on_entry);
	sp_on_entry = new_sp_on_entry;
#endif
	__real_enter(entry_point);
}

int __real_load_one_phdr(unsigned long base_addr, int fd, unsigned long vaddr, unsigned long offset,
	unsigned long memsz, unsigned long filesz, _Bool read, _Bool write, _Bool exec);
int __wrap_load_one_phdr(unsigned long base_addr, int fd, unsigned long vaddr, unsigned long offset,
	unsigned long memsz, unsigned long filesz, _Bool read, _Bool write, _Bool exec)
{
	int ret = __real_load_one_phdr(base_addr, fd, vaddr, offset,
		memsz, filesz, read, write, exec);
	if (ret == 0 && exec)
	{
		/* XXX: can't remember what I was thinking when I wrote this code or the comment
		 * below, but I assume it was something about how we instrument the inferior
		 * ld.so. Here we seem to be intercepting the action, in donald, of loading one
		 * phdr. Whereas "running the usual function" means trap_all_mappings, above,
		 * i.e. enumerating all mappings in one big go using librunt, rather than
		 * trapping them as we go along, which we could do from this function.
		 */
		/* HMM. Maybe don't do this, just make librunt work and run the usual function?
		 * Problem is that the parts of librunt that derive from liballocs assume that
		 * a libdl-style runtime is available. Ideally it would not do so, so that even
		 * if librunt is linked into a statically linked executable, it can still do
		 * things. Is this feasible?
		 * 
		 * We could simply link libdl into our program, making it available. Not sure
		 * if librunt will work in such a context, but clearly it should.
		 *
		 * However, once we do this, our fake temporary_link_map seems like the wrong
		 * thing. We make a DT_DEBUG pointing at the inferior's link map. By contrast,
		 * a local libdl would have its own link map.
		 *
		 * Is it possible to implement a chain loader simply by dlopening the dynamic
		 * loader and then loading it? We would have to un-relocate it, assuming we
		 * can't prevent dlopen from relocating it. That sounds nasty.
		 *
		 * A third way might be to splice it into the link map ourselves, without going
		 * through dlopen. But that sounds horrific.
		 *
		 * The least bad option seems to be to use functions from libsystrap that don't
		 * require librunt, and/or to fake up just enough of librunt that we can call
		 * ones that do. We do that faking-up in chain.c
		 */
	}
	return ret;
}
