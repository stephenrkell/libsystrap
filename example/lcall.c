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
#include <wchar.h>
#include <assert.h>
#include "systrap.h"
#include "relf.h"
#include "trace-syscalls.h"

#include <asm/ldt.h>
#include <unistd.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <sys/mman.h>
#include <linux/memfd.h>
#include <string.h> /* for memcpy */

/* This is an open-hashed table keyed on 12 bits from the lower 32
 * of the trap site. Each word is an absolute linear address, and
 * each is unique in its lower 32 bits. Each is stored at an offset
 * found by one of 21 hash functions, i.e. there are <=21 places at
 * which any given 64-bit pattern may be stored, and searching in
 * sequence the entries indexed by hash_0(k), hash_1(k), ... will
 * find the value stored for a 32-bit key k.
 *
 * We need to store the retaddr, not the site addr, because that is
 * what the lcall instruction puts on the stack, even if it is just
 * the lower 32 bits of it.
 */
uintptr_t __systrap_lcall_retaddrs[4096] __attribute__((visibility("hidden")));
void __systrap_call_handler_with_retaddr_restore(); /* asm */

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
	if (debug_level > 5)
	{
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
 * on uniqueness may be the best thing here. */

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
extern void __systrap_lcall_handler_template(void); /* code snippet in our text */
extern void __systrap_lcall_handler(void);          /* absolute symbol */

#ifdef __x86_64__
__asm__(".text \n\
	.globl __systrap_lcall_handler_template               \n\
	__systrap_lcall_handler_template:                     \n\
	"/* 1f: */" .byte 0xea, 0x26, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f  # ljmp $0x1f1f,$0x1f1f1f26 \n\
	"/* 26: */" .byte 0xea, 0x2d, 0x1f, 0x1f, 0x1f, 0x33, 0x00  # ljmp   $0x33,$0x1f1f1f2d \n\
	                                                            # now we are 64-bit again \n\
	"/* 2d: */" movabs $0x123456789abcdef0, %r11  # movabs immediate starts with the third byte \n\
	"/* 37: */" jmp *%r11                         # 3-byte indirect jmp \n\
	");
/* How are sigreturn and clone expected to work along the lcall path?
 * Sigreturn currently works... how? From do-syscall.h:
         * To do a sigreturn, we simply restore the user's stack pointer
         * to what it was at the site of the trap... i.e. do the same sigreturn
         * that the original code was trying to do, just from a different code address.
 * So, perhaps step 1 is to ensure that the in-frame %rsp is accurate.
 */
#define SYSTRAP_LCALL_HANDLER_LENGTH (0x3a - 0x1f)
#define SYSTRAP_LCALL_HANDLER_8BYTE_OFFSET (0x2d + 2 - 0x1f)
__asm__(".set __systrap_lcall_handler, 0x1f1f1f1f\n\
         .size __systrap_lcall_handler, " stringifx(SYSTRAP_LCALL_HANDLER_LENGTH) "\n");
#else
// FIXME: something not bogus please
#define SYSTRAP_LCALL_HANDLER_LENGTH (0x3a - 0x1f)
#define SYSTRAP_LCALL_HANDLER_8BYTE_OFFSET (0x2d + 2 - 0x1f)
#endif

void map_selector_pages(void)
{
	int the_fd = memfd_create("selector", MFD_CLOEXEC/*|MFD_HUGETLB*//*|MFD_HUGE_2MB*/);
	if (the_fd == -1) warnx("memfd_create failed");
	assert(the_fd != -1);
	/* do it in superpages (TODO: restore this / figure out why HUGETLB doesn't work) */
#define SELECTOR_MAPPING_UNIT 2097152
	int ret = ftruncate(the_fd, SELECTOR_MAPPING_UNIT);
	if (ret != 0) warnx("ftruncate");
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
	mprotect((void*) 0x1f1f1000, 4096, PROT_READ|PROT_WRITE);
	memcpy((void*) 0x1f1f1f1f, __systrap_lcall_handler_template, SYSTRAP_LCALL_HANDLER_LENGTH);
	void *tgt = __systrap_call_handler_with_retaddr_restore;
	memcpy((char*) 0x1f1f1f1f + SYSTRAP_LCALL_HANDLER_8BYTE_OFFSET, &tgt, 8);
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
