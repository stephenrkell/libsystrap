/*
 * trap.c
 *
 * This is the mechanism that reads the code to be run, and replaces
 * system call instructions with traps to gain control of the execution
 * flow.
 */

/* Basic idea:
 * - write-protect all executable pages
 *     -- using /proc/self/maps to enumerate them?
 *	YES, but must read using raw syscalls.
 *
 * - makes them writable, breakpoint any syscall instrs
 * - ... and then makes them unwritable again
 *
 * PROBLEM: vdso and vsyscall pages probably can't be write-protected
 * -- can we just override them? HMM.
 *
 */

#define _GNU_SOURCE
#include "raw-syscalls-impl.h"
/* Don't use C library calls from this code! We run before the
 * C library is initialised. Also, the definitions in asm/ conflict
 * with some libc headers, particularly typedefs related to signal
 * handling. We use inline assembly to make the few system calls
 * that we need. */
#include <sys/mman.h>
#include <stdint.h>
#include <string.h>
// #include <stdlib.h>
void qsort(void *base, size_t nmemb, size_t size,
                  int (*compar)(const void *, const void *));
#include <stdarg.h>
#include <stdio.h>
#ifdef __linux__
#include <alloca.h>
#endif
#ifdef __FreeBSD__
#include <stdlib.h>
#include <fcntl.h>
#endif
#include <err.h>
#include <link.h>
#include <assert.h>
#include <librunt.h>
#include <relf.h>
#include <vas.h>
#include <dso-meta.h>
#include "systrap_private.h"
#include "do-syscall.h"

/* For clients building a standalone executable and wanting a simple test case, 
 * we allow them to set a test trap. */
void *__libsystrap_ignore_ud2_addr;

static int sleep_for_seconds;
static int stop_self;
static int self_pid;

extern int etext;

unsigned long read_hex_num(const char **p_c, const char *end) __attribute__((visibility("hidden")));
unsigned long read_hex_num(const char **p_c, const char *end)
{
	unsigned long cur = 0;
	while ((*p_c != end && (**p_c >= '0' && **p_c <= '9'))
			|| (**p_c >= 'a' && **p_c <= 'f'))
	{
		cur <<= 4;
		cur += ((**p_c >= '0' && **p_c <= '9') ? **p_c - '0'
				 : 10 + **p_c - 'a');
		++(*p_c);
	}
	return cur;
}

void replace_instruction_with(unsigned char *pos, unsigned len,
		unsigned char const *replacement, unsigned replacement_len)
{
	assert(len >= replacement_len);
	unsigned char *begin = pos;
	unsigned char *end = pos + len;
	while (pos != end)
	{
		assert(end - pos > 0);
		if (pos - begin >= replacement_len) *pos++ = 0x90 /* nop */;
		else
		{
			unsigned char repl = replacement[pos - begin];
			*pos++ = repl;
		}
	}
}

static void insert_lcall_trap_site_with_retaddr(void *retaddr_pos, intptr_t bytes)
{
	/* Open "hashing"... */
	uintptr_t retaddr = (uintptr_t) retaddr_pos;
	unsigned shift = 0;
#define MAX_SHIFT  (32-LCALL_LOG_NRETADDRS+1)
	while (shift < MAX_SHIFT && __systrap_lcall_retaddrs[(retaddr >> shift) & ((1ul << LCALL_LOG_NRETADDRS) - 1)]) { ++shift; }
	if (shift == MAX_SHIFT) abort(); // open hashing failed... FIXME: handle this properly
	// We found an unused (null) entry. Store the site there. That's it!
	__systrap_lcall_retaddrs[(retaddr >> shift) & ((1ul << LCALL_LOG_NRETADDRS) - 1)] = retaddr;
#undef MAX_SHIFT
}

void replace_syscall_with_lcall(unsigned char *pos, unsigned len)
{
	assert(len >= 2);
	unsigned char replacement_ud2[] = { (unsigned char) 0x0f, (unsigned char) 0x0b }; // ud2
	unsigned char replacement_lcall[] = { (unsigned char) 0xff, (unsigned char) 0x98 }; // lcall  *0xnnnnnnnn(%rax) 
#ifdef __i386__
	if (is_sysenter_instr(pos, pos + len) &&
			(uintptr_t) pos >= (uintptr_t) fake_sysinfo &&
			(uintptr_t) pos <  (uintptr_t) fake_sysinfo + KERNEL_VSYSCALL_MAX_SIZE)
	{
		sysinfo_sysenter_offset = (uintptr_t) pos - (uintptr_t) fake_sysinfo;
		/* We're instrumenting the sysenter position in the *fake* ld.so.
		 * Remember its offset. */
		unsigned char *forward_pos = pos;
		while (!is_int80_instr(forward_pos, forward_pos + 2)
			&& forward_pos <= (unsigned char *) fake_sysinfo + KERNEL_VSYSCALL_MAX_SIZE - 2)
		{ ++forward_pos; }
		if (forward_pos <= (unsigned char *) fake_sysinfo + KERNEL_VSYSCALL_MAX_SIZE - 2)
		{
			assert(is_int80_instr(forward_pos, forward_pos + 2));
			sysinfo_int80_offset = (uintptr_t) forward_pos - (uintptr_t) fake_sysinfo;
		}
	}
#endif
	int32_t bytes; memcpy(&bytes, pos+len, 4); // HACK
	if (bytes > 2097152) // HACK: more precise please
	{
		debug_printf(1, "Replacing syscall at %p with trap (lcall via *0xPUNNED(%rax))\n", pos);
		insert_lcall_trap_site_with_retaddr(pos + 6, bytes);
		replace_instruction_with(pos, len, replacement_lcall, sizeof replacement_lcall);
	}
	else
	{
		debug_printf(1, "Replacing syscall at %p with trap (ud2)\n", pos);
		replace_instruction_with(pos, len, replacement_ud2, sizeof replacement_ud2);
	}
}

void walk_instructions(unsigned char *pos, unsigned char *end,
	void (*cb)(unsigned char *pos, unsigned len, void *arg), void *arg)
{
	unsigned char *cur = pos;
	while (cur < end)
	{
		/* FIXME: if our mapping includes some non-instructions, 
		 * and these accidentally decode into multi-byte instructions,
		 * we might get misaligned here. We *will* catch this when
		 * we do the paranoid second scan, but it would be better not
		 * to rely on this. */
		unsigned len = instr_len(cur, end);
		cb(cur, len, arg);
		cur += (len ? len : 1);
	}
}

int set_default_trap(unsigned char *pos, unsigned len, void *arg_ignored)
{
	replace_syscall_with_lcall(pos, len);
	return 0;
}
struct set_trap_closure
{
	set_trap_fn_t *set_trap;
	void *set_trap_arg;
};

static void maybe_set_trap_cb(unsigned char *pos, unsigned len, void *set_trap_closure_as_void)
{
	struct set_trap_closure *s = set_trap_closure_as_void;
	if (is_syscall_instr(pos, pos + len))
	{
		s->set_trap(pos, len, s->set_trap_arg);
	}
}

void trap_one_instruction_range(unsigned char *begin_instr_pos, unsigned char *end_instr_pos,
	_Bool is_writable, _Bool is_readable, _Bool preserve_exec, set_trap_fn_t *set_trap, void *set_trap_arg)
{
	const void *begin_page = ROUND_DOWN_PTR_TO_PAGE((const void *) begin_instr_pos);
	const void *end_page = ROUND_UP_PTR_TO_PAGE((const void *) end_instr_pos);
	if (!is_writable)
	{
		int ret __attribute__((unused)) = raw_mprotect(begin_page, end_page - begin_page,
			PROT_READ | PROT_WRITE | (preserve_exec ? PROT_EXEC : 0));

		/* If we failed, it might be on the vdso page or similar. However,
		 * as of at least Linux 5.15, possibly earlier, it does seem to be
		 * possible to make the vdso pages writable. */
		assert(ret == 0 || (intptr_t) begin_page < 0); // XXX: this "< 0" check is sysdep
		if (ret != 0 && (intptr_t) begin_page < 0)
		{
			debug_printf(1, "Couldn't rewrite nor protect mapping (vdso?) at %p\n", begin_page);
			return;
		}
	}
	/* What to do about byte sequences that look like syscalls
	 * but are "in the middle" of instructions?
	 * How do we know where to *start* parsing an instruction stream?
	 *
	 * For now, we
	 * - start parsing at the beginning only
	 * - do fixups
	 * - then do another pass where we detect remaining syscall-instruction-alikes
	 * - ... and warn if we see any
	 *
	 * What about ud2-alikes that don't correspond to replaced instructions?
	 * No problem: we just need to remember which sites we replaced.
	 * If we hit a ud2 that's not at such a site, we just do ud2.
	 * FIXME: implement this.
	 */
	// char debug_buf[line_end_pos - line_begin_pos + 1];
	// strncpy(debug_buf, line_begin_pos, line_end_pos - line_begin_pos);
	// debug_buf[sizeof debug_buf - 1] = '\0';
	// // assert that line_end_pos
	debug_printf(1, "Scanning for syscall instructions within %p-%p (%s)\n",
		begin_instr_pos, end_instr_pos, /*debug_buf */ "FIXME: reinstate debug printout");
	struct set_trap_closure clos = { .set_trap = set_trap, .set_trap_arg = set_trap_arg };
	walk_instructions(begin_instr_pos, end_instr_pos, maybe_set_trap_cb, &clos);
	/* Now the paranoid second scan: check for in-betweens. */
	unsigned char *instr_pos = (unsigned char *) begin_page; // start from the real beginning
	while (instr_pos != end_page)
	{
		if (is_syscall_instr(instr_pos, end_instr_pos))
		{
			debug_printf(1, "Warning: after instrumentation, bytes at %p "
				"could make a syscall on violation of control flow integrity\n",
				instr_pos);
		}
		++instr_pos;
	}
	// restore original perms
	if (!is_writable)
	{
		int ret __attribute__((unused)) = raw_mprotect(begin_page, end_page - begin_page,
			(is_readable ? PROT_READ : 0)
		|                  PROT_EXEC
		);
		assert(ret == 0);
	}
}

_Bool addr_is_in_ld_so(const void *pos)
{
	extern void *__tls_get_addr(); // in ld.so
	static struct link_map *ld_so_link_map;
	static void *ld_so_end;
	if (!ld_so_link_map)
	{
		debug_printf(1, "_r_debug is at %p\n", &_r_debug);
		ld_so_link_map = get_highest_loaded_object_below(__tls_get_addr);
		debug_printf(1, "We think (the real) ld.so's link map is at %p, base %p, filename %s\n",
			ld_so_link_map,
			ld_so_link_map ? (void*) ld_so_link_map->l_addr : (void*) -1,
			ld_so_link_map ? ld_so_link_map->l_name : "(no link map)");
		/* XXX: we will use get_highest_loaded_object_below on pos, but
		 * this is wrong if the real ld.so is the highest loaded object:
		 * we will deem all higher addresses to be within the ld.so. And more
		 * generally it's wrong because we don't account for the end of the ld.so.
		 * Can we apply a length check using etext from the ld.so? No, because
		 * my ld.so does not define etext. If we could get the phdrs we could
		 * find the maximum vaddr... can we do this? */
		if (ld_so_link_map) ld_so_end = get_text_segment_end_from_load_addr(
			(void*) ld_so_link_map->l_addr);
	}

	struct link_map *range_link_map = get_highest_loaded_object_below((void*) pos);
	_Bool ret = (ld_so_link_map && range_link_map &&
		ld_so_link_map == range_link_map &&
			(!ld_so_end || (uintptr_t) pos < (uintptr_t) ld_so_end));
	if (ret) debug_printf(1, "We think %p is within (the real) ld.so\n", pos);
	return ret;
}

void trap_one_executable_region_given_shdrs(unsigned char *begin,
	unsigned char *end, const char *filename,
	_Bool is_writable, _Bool is_readable, _Bool preserve_exec,
	ElfW(Shdr) *shdrs, unsigned nshdr, ElfW(Addr) laddr,
	set_trap_fn_t *set_trap, void *set_trap_arg)
{
	assert(end >= begin);
	// it's executable; scan for syscall instructions
	unsigned char *begin_instr_pos;
	unsigned char *end_instr_pos;
	/* An executable mapping might include some non-instructions
	 * that will cause our instruction walker to get misaligned.
	 * Instead, we would like to walk the *sections* individually,
	 * then re-traverse the whole thing. So we mmap the section
	 * header table. PROBLEM: we can't re-open a file that is
	 * guaranteed to be the same. */
	const void *first_section_start = NULL;
	const void *last_section_end = (void*)-1;
	if (shdrs)
	{
		uintptr_t ret = find_section_boundary((uintptr_t) begin - laddr, SHF_EXECINSTR, 0,
			shdrs, nshdr, NULL);
		if (ret && ret != (uintptr_t)-1) first_section_start = (const void *) laddr + ret;
		else debug_printf(5, "in executable mapping %p-%p, could not get last section boundary\n",
			begin, end);
		ret = find_section_boundary((uintptr_t) end - laddr, SHF_EXECINSTR, 1,
			shdrs, nshdr, NULL);
		if (ret && ret != (uintptr_t) -1) last_section_end = (const void *) laddr + ret;
		else debug_printf(5, "in executable mapping %p-%p, could not get first section boundary\n",
			begin, end);
	}

	/* These might return respectively (void*)-1 and (void*)0, to signify
	 * "no instructions in that range, according to section headers".
	 * The section headers are pretty reliable, so we choose not to
	 * conservatively include this region. Instead we'll silently iterate
	 * over zero instructions. This "no instructions found" usually happens
	 * for ld.so whose text segment has been remapped RW and written to by
	 * the ld.so bootstrap phase. This means it gets split into two /proc
	 * lines, only one of which contains any instructions, so we hit the
	 * "no instructions" case for the second one. Note that we will do a
	 * "paranoid scan" anyway. */

	if (first_section_start && (unsigned char *) first_section_start <= end)
	{
		begin_instr_pos = (unsigned char *) first_section_start;
	}
	else
	{
		debug_printf(1, "in executable mapping %p-%p, could not use shdrs"
				" to locate first instruction after %p (file %s, first section %p)\n",
			begin, end, begin, filename, first_section_start);
		begin_instr_pos = (unsigned char *) end;
	}

	if (last_section_end && last_section_end != (void*) -1
			&& (unsigned char *) last_section_end >= begin)
	{
		debug_printf(1, "in executable mapping %p-%p, we think the last section ends at %p\n",
			begin, end, last_section_end);
		end_instr_pos = (unsigned char *) last_section_end;
	}
	else
	{
		debug_printf(1, "in executable mapping %p-%p, could not use shdrs"
				" to locate previous instruction before %p (file %s, last section %p)\n",
			begin, end, end, filename, last_section_end);
		end_instr_pos = (unsigned char *) begin;
	}
	
	if ((unsigned char *) end_instr_pos > (unsigned char *) begin_instr_pos)
	{
		if (is_writable && 0 == strcmp(filename, "[stack]")) // FIXME: sysdep
		{
			/* We've found an executable stack region. These are generally 
			 * bad for security. HACK: let's try just de-executabling it. */
			debug_printf(0, "removing execute permission from stack region %p-%p", begin, end);
			int ret = raw_mprotect(begin, (char*) end - (char*) begin, 
				PROT_READ | PROT_WRITE);
			if (ret != 0) debug_printf(0, "failed to remove execute permission from stack region %p-%p", begin, end);
		}
		else
		{
			trap_one_instruction_range(begin_instr_pos, end_instr_pos, is_writable, is_readable,
				preserve_exec, set_trap, set_trap_arg);
		}
	}
}
void trap_one_executable_region(unsigned char *begin, unsigned char *end, const char *filename,
	_Bool is_writable, _Bool is_readable, _Bool preserve_exec,
	set_trap_fn_t *set_trap, void *set_trap_arg)
{
	// Q: why was this apparently not necessary previously?
	// A. it was handled by a failure to mprotect()-to-writable, but that
	// failure can no longer be relied on (kernel changes)
	if (0 == strncmp(filename, "[vdso", 5))
	{
		return;
	}
	struct file_metadata *fm = __runt_files_metadata_by_addr(begin);
	trap_one_executable_region_given_shdrs(begin, end, filename, is_writable,
		is_readable, preserve_exec,
		fm ? fm->shdrs : NULL, (fm && fm->ehdr) ? fm->ehdr->e_shnum : 0, fm ? fm->l->l_addr : 0,
		set_trap, set_trap_arg);
}

void handle_sigill(int n) __attribute__((visibility("hidden")));
struct FILE;
int systrap_debug_level __attribute__((visibility("hidden"))) = 0;

/* We initialize our error-reporting stuff, but don't actually 
 * set up any traps. That's left to the client. */
__attribute__((constructor))
static void startup(void)
{
	char *debug_level_str = getenv("TRAP_SYSCALLS_DEBUG");
	char *sleep_for_seconds_str = getenv("TRAP_SYSCALLS_SLEEP_FOR_SECONDS");
	char *stop_self_str = getenv("TRAP_SYSCALLS_STOP_SELF");
	stop_self = (stop_self_str != NULL);
	struct __asm_timespec one_second = { /* seconds */ 1, /* nanoseconds */ 0 };
	if (debug_level_str) systrap_debug_level = atoi(debug_level_str);
	if (sleep_for_seconds_str) sleep_for_seconds = atoi(sleep_for_seconds_str);
	debug_printf(1, "Debug level is %s=%d.\n", debug_level_str, systrap_debug_level);
	if (stop_self) {
		self_pid = raw_getpid();
		debug_printf(1, "TRAP_SYSCALLS_STOP_SELF is set, sending SIGSTOP to self (pid %d)\n", self_pid);
		raw_kill(self_pid, SIGSTOP);
	}
	debug_printf(1, "TRAP_SYSCALLS_SLEEP_FOR_SECONDS is %s, pausing for %d seconds", sleep_for_seconds_str, sleep_for_seconds);
	for (int i = 0; i < sleep_for_seconds; i++) {
		raw_nanosleep(&one_second, NULL);
		debug_printf(1, ".");
	}
	debug_printf(1, "\n");
}

void __libsystrap_force_init(void)
{
	startup();
}

#ifdef __linux__
long clone3_emulated_replacement(struct generic_syscall *s)
{
	struct clone_args *cl_args = (struct clone_args *) s->args[0];
	// size_t size = s->args[1];
	/* Build a vanilla clone generic_syscall and let it handle the rest.
	 * All the hairy stuff is in do-syscall.h. */
	struct generic_syscall gs = MKGS5(SYS_clone,
		/* flags */ cl_args->flags | (cl_args->exit_signal & 0xff),
		/* stack */ (uintptr_t) (cl_args->stack ? ((char*)(uintptr_t)cl_args->stack + cl_args->stack_size) : NULL),
		/* parent_tid */ (pid_t *)(uintptr_t) cl_args->parent_tid,
#if defined(__x86_64__)
		/* child_tid */ (pid_t *)cl_args->child_tid,
		/* tls */ cl_args->tls
#elif defined(__i386__) /* last two arguments are reversed on this arch */
		/* tls */ cl_args->tls,
		/* child_tid */ (pid_t *)(uintptr_t) cl_args->child_tid
#else
#error "Unrecognised architecture -- check raw clone() signature on this platform."
#endif
		);
	gs.saved_context = s->saved_context;
	gs.site = s->site;
#if 0
	do_generic_syscall_and_fixup(&gs); // does post-handling and sets return value in fixed-up context
#else
	// FIXME: duplicating this code here to avoid the dreaded "impossible constraints"
	// from the do_generic_syscall_and_fixup call.
	long ret = do_clone(&gs);
#if 0
	// FIXME: see note about stack handling in do_generic_syscall_and_fixup
	fixup_sigframe_for_return(gs.saved_context, ret,
		trap_len(&gs.saved_context->uc.uc_mcontext),
		(ret == 0) ? (void*) (gs.args[1] /* see fake_arg1 comment in do_clone()  */)
			: NULL);
#else
	return ret;
#endif
#endif
}
#endif

__attribute__((visibility("hidden")))
int trap_at_vperm_range_cb(struct vperm_range *r, void *arg)
{
	/* Can we get the trapping address as an ELF file with shdrs, librunt-wise? */
	struct file_metadata *fm = __runt_files_metadata_by_addr((void*)(uintptr_t) r->addr);
	if (!fm)
	{
		/* It might be that we're doing dlopen of the relevant code Right Now,
		 * so librunt hasn't had the notification yet. If we fish out a link map,
		 * it can still add the metadata for us. Let's try that. */
		struct link_map *l = get_highest_loaded_object_below((void*)(uintptr_t) r->addr);
		if (l) fm = __runt_files_get_or_create_metadata(l);
		assert(fm);
		if (!fm) abort();
	}
	/* Just what trap_one_mapping would have done */
	trap_one_executable_region_given_shdrs(
		(unsigned char *)(uintptr_t) r->addr, (unsigned char *)((uintptr_t) r->addr + (r->npages << LOG_MIN_PAGE_SIZE)),
		fm->filename,
		/* is_writable already? if only if it has writable vperms */ prot_from_vperms(r->perms) & PROT_WRITE,
		/* readable? */ 1, /* preserve_exec */ 0, // <-- no need to keep it x; for now, we know it's not in the ld.so
		fm ? fm->shdrs : NULL, (fm && fm->ehdr) ? fm->ehdr->e_shnum : 0, fm ? fm->l->l_addr : 0,
		/* set_trap */ set_default_trap, /*set_trap_arg*/ NULL);
	/* Now we can make it really executable. XXX: here we always take away write permission;
	 * if the user asked for a RWX mapping, we need to do something else here. */
	mprotect((void*)(uintptr_t) r->addr, r->npages << LOG_MIN_PAGE_SIZE, PROT_READ | PROT_EXEC);

	/* We can delete the vperm range now. */
	return VPERM_A_DELETE;
}
