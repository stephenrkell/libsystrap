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
/* Don't use C library calls from this code! We run before the
 * C library is initialised. Also, the definitions in asm/ conflict
 * with some libc headers, particularly typedefs related to signal
 * handling. We use inline assembly to make the few system calls
 * that we need. */
#include "raw-syscalls.h"
#ifdef __linux__
#define sigset_t __asm_sigset_t
#endif
#include <sys/mman.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#ifdef __linux__
#include <alloca.h>
#endif
#ifdef __FreeBSD__
#include <stdlib.h>
#include <fcntl.h>
#endif
#include <err.h>
#include "systrap_private.h"
#include "do-syscall.h"
#include "elfutil.h"
#include <maps.h> /* from liballocs -- GAH, cyclic dependency */

/* For clients building a standalone executable and wanting a simple test case, 
 * we allow them to set a test trap. */
void *__libsystrap_ignore_ud2_addr;

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

static const void *our_text_begin_address;
static const void *our_text_end_address;

static void replace_syscall(unsigned char *pos, unsigned len)
{
	debug_printf(1, "Replacing syscall at %p with trap\n", pos);
	
	assert(len >= 2);
	unsigned char *end = pos + len;
	while (pos != end)
	{
		switch (end - pos)
		{
			/* ud2 is 0x0f 0x0b */
			case 2: *pos++ = 0x0f; break;
			case 1: *pos++ = 0x0b; break;
			case 0: assert(0);
			default: *pos++ = 0x90; /* nop */ break;
		}
	}
}

static void walk_instructions(unsigned char *pos, unsigned char *end,
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
	if (is_syscall_instr(pos, pos + len)) replace_syscall(pos, len);
}

#define ROUND_DOWN_PTR_TO_PAGE(p) ROUND_DOWN_PTR((p), guess_page_size_unsafe())
#define ROUND_UP_PTR_TO_PAGE(p) ROUND_UP_PTR((p), guess_page_size_unsafe())

void *__tls_get_addr(); // in ld.so

void trap_one_instruction_range(unsigned char *begin_instr_pos, unsigned char *end_instr_pos, 
	_Bool is_writable, _Bool is_readable)
{
	const void *begin_page = ROUND_DOWN_PTR_TO_PAGE((const void *) begin_instr_pos);
	const void *end_page = ROUND_UP_PTR_TO_PAGE((const void *) end_instr_pos);
	
	static struct link_map *ld_so_link_map;
	if (!ld_so_link_map)
	{
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
		/* NOTE: sometimes our own code will need to call into the dynamic
		 * loader, e.g. to call __tls_get_addr. So if we're walking the 
		 * dynamic loader, leave it executable. This isn't really an extra
		 * security weakness because our own code is in the same boat. 
		 * When we *are* the dynamic loader (emerald-style), this problem
		 * will go away, though our own code will be larger. */
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

void trap_one_executable_region(unsigned char *begin, unsigned char *end, const char *filename,
	_Bool is_writable, _Bool is_readable)
{
	// it's executable; scan for syscall instructions
	unsigned char *begin_instr_pos;
	unsigned char *end_instr_pos;
	/* An executable mapping might include some non-instructions 
	 * that will cause our instruction walker to get misaligned. 
	 * Instead, we would like to walk the *sections* individually,
	 * then re-traverse the whole thing. So we mmap the section
	 * header table. PROBLEM: we can't re-open a file that is
	 * guaranteed to be the same. */
	void *base_addr = NULL;
	const void *first_section_start = vaddr_to_nearest_instruction(
		begin, filename, 0, &base_addr);
	const void *last_section_end = vaddr_to_nearest_instruction(
		end, filename, 1, &base_addr);
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

	if (first_section_start)
	{
		begin_instr_pos = (unsigned char *) first_section_start;
	}
	else
	{
		debug_printf(0, "in executable mapping %p-%p, could not use shdrs to locate first instruction after %p (file %s); being conservative", 
			begin, end, begin, filename);
		begin_instr_pos = (unsigned char *) begin;
	}

	if (last_section_end)
	{
		end_instr_pos = (unsigned char *) last_section_end;
	}
	else
	{
		debug_printf(0, "in executable mapping %p-%p, could not use shdrs to locate previous instruction before %p (file %s); being conservative",
			begin, end, end, filename);
		end_instr_pos = (unsigned char *) end;
	}
	
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

static int process_mapping_cb(struct maps_entry *ent, char *linebuf, void *arg)
{
	/* Skip ourselves, but remember our load address. */
	void *expected_mapping_end = (void*) page_boundary_up((uintptr_t) &etext);
	if ((const unsigned char *) ent->second >= (const unsigned char *) expected_mapping_end
		 && (const unsigned char *) ent->first < (const unsigned char *) expected_mapping_end)
	{
		our_text_begin_address = (const void *) ent->first;
		our_text_end_address = (const void *) ent->second;
		
		/* Compute our load address from the phdr p_vaddr of this segment.
		 * But how do we get at our phdrs?
		 * In general I think we need to hack the linker script to define a new symbol.
		 * But for now, just use the fact that it's very likely to be the lowest text addr. */
		our_load_address = (uintptr_t) our_text_begin_address;

		debug_printf(1, "Skipping our own text mapping: %p-%p\n", 
			(void*) ent->first, (void*) ent->second);
		
		return 0; // keep going
	}

	if (ent->x == 'x')
	{
		trap_one_executable_region((unsigned char *) ent->first, (unsigned char *) ent->second,
			 ent->rest[0] ? ent->rest : NULL,
			ent->w == 'w', ent->r == 'r');
	}
	
	return 0; // keep going
}

static void handle_sigill(int num);

int debug_level __attribute__((visibility("hidden")));
int sleep_for_seconds __attribute__((visibility("hidden")));
int stop_self __attribute__((visibility("hidden")));
int self_pid __attribute__((visibility("hidden")));
FILE **p_err_stream __attribute__((visibility("hidden")));

/* We initialize our error-reporting stuff, but don't actually 
 * set up any traps. That's left to the client. */
static void __attribute__((constructor)) startup(void)
{
	char *debug_level_str = getenv("TRAP_SYSCALLS_DEBUG");
	char *sleep_for_seconds_str = getenv("TRAP_SYSCALLS_SLEEP_FOR_SECONDS");
	char *stop_self_str = getenv("TRAP_SYSCALLS_STOP_SELF");
	stop_self = (stop_self_str != NULL);
	struct __asm_timespec one_second = { /* seconds */ 1, /* nanoseconds */ 0 };
	if (debug_level_str) debug_level = atoi(debug_level_str);
	if (sleep_for_seconds_str) sleep_for_seconds = atoi(sleep_for_seconds_str);
	debug_printf(1, "Debug level is %s=%d.\n", debug_level_str, debug_level);
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

void trap_all_mappings(void)
{
	/* When we process mappings, we do mprotect()s, which can change the memory map, 
	 * including removing/adding lines. So there's a race condition unless we eagerly
	 * snapshot the map. Do that here. */
	int fd = raw_open("/proc/self/maps", O_RDONLY);
	if (fd != -1)
	{
		/* We run during startup, so the number of distinct /proc lines should be small. */
	#define MAX_LINES 1024
		char *lines[MAX_LINES];
		int n = 0;
		ssize_t linesz;
		char linebuf[8192];
		while (-1 != (linesz = get_a_line_from_maps_fd(linebuf, sizeof linebuf, fd)))
		{
			lines[n] = alloca(linesz + 1);
			if (!lines[n]) abort();
			strncpy(lines[n], linebuf, linesz);
			lines[n][linesz] = '\0';
			++n;
		}
		
		/* Now we have an array containing the lines. */
		struct maps_entry entry;
		for (int i = 0; i < n; ++i)
		{
			int ret = process_one_maps_entry(lines[i], &entry, process_mapping_cb, NULL);
			if (ret) break;
		}

		raw_close(fd);
	}
}

void install_sigill_handler(void)
{
	/* Install our SIGILL (was SIGTRAP, but that interferes with gdb) handler.
	 * Linux seems to require us to provide a restorer; the code is in restore_rt. */
#ifndef SA_RESTORER
//#define SA_RESTORER 0x04000000u
#error "NO SA_RESTORER set; are you including the asm signal.h?"
#endif
	struct __asm_sigaction action = {
		.sa_handler = &handle_sigill,
		.sa_flags = SA_RESTORER | SA_NODEFER
		#ifndef __FreeBSD__
		, .sa_restorer = restore_rt
		#endif
	};
	struct __asm_sigaction oldaction;
	int ret = raw_rt_sigaction(SIGILL, &action, &oldaction);
	if (ret != 0) abort();
	return;
}

// For debug printing inside handle_sigill we have to know
// that it's our own debug printing in order to filter it
// out of the footprints, hence this noinline function
// rather than using the normal macro
__attribute__ ((noinline)) static void _handle_sigill_debug_printf(int level, const char *fmt, ...) {
	 va_list vl;
	 va_start(vl, fmt);
	 if ((level) <= debug_level) {
		  vfprintf(*p_err_stream, fmt, vl);
		  fflush(*p_err_stream);
	 }
	 va_end(vl);
}

/* We may or may not have syscall names linked in.
 * This is just to avoid a dependency on our syscall interface spec.  */
extern const char *syscall_names[SYSCALL_MAX + 1] __attribute__((weak));
static void handle_sigill(int n)
{
	unsigned long *frame_base = __builtin_frame_address(0);
	struct ibcs_sigframe *p_frame = (struct ibcs_sigframe *) (frame_base + 1);

	/* Decode the syscall using sigcontext. */
	_handle_sigill_debug_printf(1, "Took a trap from instruction at %p", p_frame->uc.uc_mcontext.MC_REG(rip, RIP));
#ifdef EXECUTABLE
	if (p_frame->uc.uc_mcontext.MC_REG(rip, RIP) == (uintptr_t) ignore_ud2_addr)
	{
		_handle_sigill_debug_printf(1, " which is our test trap address; continuing.\n");
		resume_from_sigframe(0, p_frame, 2);
		return;
	}
#endif
	unsigned long syscall_num = (unsigned long) p_frame->uc.uc_mcontext.MC_REG(rax, RAX);
	assert(syscall_num >= 0);
	assert(syscall_num < SYSCALL_MAX);
	_handle_sigill_debug_printf(1, " which we think is syscall %s/%d\n",
		&syscall_names[0] ? syscall_names[syscall_num] : "(names not linked in)", syscall_num);

	/* FIXME: check whether this syscall creates executable mappings; if so,
	 * we make them nx, do the rewrite, then make them x. */

	struct generic_syscall gsp = {
		.saved_context = p_frame,
		.syscall_number = syscall_num,
		.args = {
			p_frame->uc.uc_mcontext.MC_REG(rdi, RDI),
			p_frame->uc.uc_mcontext.MC_REG(rsi, RSI),
			p_frame->uc.uc_mcontext.MC_REG(rdx, RDX),
			p_frame->uc.uc_mcontext.MC_REG(r10, R10),
			p_frame->uc.uc_mcontext.MC_REG(r8, R8),
			p_frame->uc.uc_mcontext.MC_REG(r9, R9)
		}
	};

	do_syscall_and_resume(&gsp); // inline
}
