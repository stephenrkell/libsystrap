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
#include <relf.h>
#include <vas.h>
#include <librunt.h>
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

void replace_syscall_with_ud2(unsigned char *pos, unsigned len)
{
	assert(len >= 2);
	unsigned char replacement[] = { (unsigned char) 0x0f, (unsigned char) 0x0b }; // ud2
	debug_printf(1, "Replacing syscall at %p with trap\n", pos);
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
	replace_instruction_with(pos, len, replacement, sizeof replacement);
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

static void instruction_cb(unsigned char *pos, unsigned len, void *arg)
{
	if (is_syscall_instr(pos, pos + len))
	{
		replace_syscall_with_ud2(pos, len);
	}
}

void *__tls_get_addr(); // in ld.so

void trap_one_instruction_range(unsigned char *begin_instr_pos, unsigned char *end_instr_pos,
	_Bool is_writable, _Bool is_readable)
{
	const void *begin_page = ROUND_DOWN_PTR_TO_PAGE((const void *) begin_instr_pos);
	const void *end_page = ROUND_UP_PTR_TO_PAGE((const void *) end_instr_pos);

	static struct link_map *ld_so_link_map;
	if (!ld_so_link_map)
	{
		/* NOTE: sometimes our own code will need to call into the dynamic
		 * linker, e.g. to call __tls_get_addr. So if we're walking the
		 * dynamic linker, leave it executable.
		 *
		 * If we are a preload library, this isn't really an extra
		 * security weakness because our own code is in the same boat.
		 *
		 * If we *are* the dynamic linker, this problem goes away, because
		 * we never take away our own permissions. */
		ld_so_link_map = get_highest_loaded_object_below(__tls_get_addr);
	}
	debug_printf(1, "_r_debug is at %p\n", &_r_debug);
	debug_printf(1, "We think ld.so's link map is at %p, base %p, filename %s\n",
		ld_so_link_map,
		ld_so_link_map ? (void*) ld_so_link_map->l_addr : (void*) -1,
		ld_so_link_map ? ld_so_link_map->l_name : "(can't deref null)");

	struct link_map *range_link_map = get_highest_loaded_object_below(begin_instr_pos);
	_Bool range_is_in_ld_so = (ld_so_link_map && range_link_map &&
		ld_so_link_map == range_link_map);

	if (!is_writable)
	{
		int ret = raw_mprotect(begin_page, end_page - begin_page,
			PROT_READ | PROT_WRITE | (range_is_in_ld_so ? PROT_EXEC : 0));

		/* If we failed, it might be on the vdso page. */
		assert(ret == 0 || (intptr_t) begin_page < 0);
		if (ret != 0 && (intptr_t) begin_page < 0)
		{
			/* vdso/vsyscall handling: since we can't rewrite the instructions on these
			 * pages, instead we should execute-protect them. Then, when we take a trap,
			 * we need to emulate the instructions there. FIXME: implement this. */

			debug_printf(1, "Couldn't rewrite nor protect vdso mapping at %p\n", begin_page);
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
	/* If our range contains a signal restorer, it will do a sigreturn.
	 * We don't want to trap this.
	 * So we need to figure out where the libc's restorer is, and skip over it.
	 * We leave this mostly as the client's business. Instead we allow the client
	 * to define a __systrap_skip_ranges[]. */
	walk_instructions(begin_instr_pos, end_instr_pos, instruction_cb, NULL);
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
		int ret = raw_mprotect(begin_page, end_page - begin_page,
			(is_readable ? PROT_READ : 0)
		|                  PROT_EXEC
		);
		assert(ret == 0);
	}
}

void trap_one_executable_region_given_shdrs(unsigned char *begin,
	unsigned char *end, const char *filename,
	_Bool is_writable, _Bool is_readable,
	ElfW(Shdr) *shdrs, unsigned nshdr, ElfW(Addr) laddr)
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
		ret = find_section_boundary((uintptr_t) end - laddr, SHF_EXECINSTR, 1,
			shdrs, nshdr, NULL);
		if (ret && ret != (uintptr_t) -1) last_section_end = (const void *) laddr + ret;
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
			trap_one_instruction_range(begin_instr_pos, end_instr_pos, is_writable, is_readable);
		}
	}
}
void trap_one_executable_region(unsigned char *begin, unsigned char *end, const char *filename,
	_Bool is_writable, _Bool is_readable)
{
	struct file_metadata *fm = __runt_files_metadata_by_addr(begin);
	trap_one_executable_region_given_shdrs(begin, end, filename, is_writable,
		is_readable,
		fm ? fm->shdrs : NULL, fm ? fm->ehdr->e_shnum : 0, fm ? fm->l->l_addr : 0);
}

void handle_sigill(int n) __attribute__((visibility("hidden")));
struct FILE;
int systrap_debug_level __attribute__((visibility("hidden"))) = 0;

/* We initialize our error-reporting stuff, but don't actually 
 * set up any traps. That's left to the client. */
static void __attribute__((constructor)) startup(void)
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

	//trap_all_mappings();
	// install_sigill_handler();
}

void __libsystrap_force_init(void)
{
	startup();
}

void install_sigill_handler(void)
{
	/* Install our SIGILL (was SIGTRAP, but that interferes with gdb) handler.
	 * Linux seems to require us to provide a restorer; the code is in restore_rt. */
#ifndef SA_RESTORER
#error "NO SA_RESTORER set; are you including the asm signal.h?"
#endif

/* Which restorer routine do we need? */
#if defined(__i386__)
#define sigill_restorer __restore
#elif defined(__x86_64__)
#define sigill_restorer __restore_rt
#else
#error "Unsupported architecture."
#endif
	// remember we are kernel-level asm sigaction, so no sigset_t
	struct __asm_sigaction action = {
		.sa_handler = &handle_sigill,
		.sa_flags = SA_RESTORER | SA_NODEFER,
		.sa_mask = ((__asm_sigset_t) -1) & ~(1ul<<(SIGILL-1))
		#ifndef __FreeBSD__
		, .sa_restorer = sigill_restorer
		#endif
	};
	struct __asm_sigaction oldaction;
	int ret =
/* FIXME: clean this up */
#ifdef __x86_64__
	raw_rt_sigaction
#else
	raw_sigaction
#endif
	(SIGILL, &action, &oldaction);
	if (ret != 0) abort();
	return;
}

