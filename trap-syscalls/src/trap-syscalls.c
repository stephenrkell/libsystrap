/*
 * trap-syscalls.c
 *
 * This is the mechanism that reads the code to be run, and replace
 * system call instructions with traps to gain control of the execution
 * flow.
 */

/* Basic idea: we are a preloaded library whose constructor
 * - write-protects all executable pages
 *     -- using /proc/self/maps to enumerate them?
 *	YES, but must read using raw syscalls.
 *
 * - makes them writable, breakpoint any syscall instrs
 * - ... and then makes them unwritable again
 *
 * PROBLEM: vdso and vsyscall pages probably can't be write-protected
 * -- can we just override them? HMM.
 *
 * */

#define _GNU_SOURCE
/* Don't use C library calls from this code! We run before the
 * C library is initialised. Also, the definitions in asm/ conflict
 * with some libc headers, particularly typedefs related to signal
 * handling. We use inline assembly to make the few system calls
 * that we need. */
#include <unistd.h>
#include <asm/signal.h>
#include <asm/fcntl.h>
#include <sys/mman.h>
#include <stdint.h>

#include "raw-syscalls.h"
#include "do-syscall.h"

/* If we build a standalone executable, we include a test trap. */
#ifdef EXECUTABLE
static void *ignore_ud2_addr;
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

extern int etext;

static int is_syscall_instr(unsigned const char *p, unsigned const char *end)
{
	if ((end >= p + 2) && *p == 0x0f && *(p+1) == 0x05) return 2;
	return 0;
}

static unsigned long read_hex_num(const char **p_c, const char *end)
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

static void replace_syscall(unsigned char *pos, unsigned char *end)
{
	write_string("Replacing syscall at ");
	write_ulong((unsigned long) pos);
	write_string(" with trap.\n");
	
	assert(end - pos >= 2);
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
	void (*cb)(unsigned char *pos, unsigned char *end, void *arg), void *arg)
{
	/* Use libopcodes. Easier said than done! We need
	 * 
	 * - -fPIC build in archive form
	 *
	 * - same for libraries it depends on (libbfd, libc, ...?)
	 * 
	 * It's never going to be as easy as "-Bstatic -lwhatever".
	 * A local build of libbfd and libopcodes and uClibc seems best.
	 */
	// HACK: for now just do what we did before
	for (unsigned char *cur = pos; cur != end; ++cur)
	{
		cb(cur, end, arg);
	}
}

static void instruction_cb(unsigned char *pos, unsigned char *end, void *arg)
{
	int syscall_instr_len = 0;
	if (0 != (syscall_instr_len = is_syscall_instr(pos, end)))
	{
		replace_syscall(pos, pos + syscall_instr_len);
	}
}

static void *page_boundary_up(void *arg)
{
	unsigned long addr = (unsigned long) arg;
	if (addr % PAGE_SIZE == 0) return arg;
	else return (void*) (PAGE_SIZE * (1 + (addr / PAGE_SIZE)));
}
static void saw_mapping(const char *line_begin_pos, const char *line_end_pos)
{
	const char *line_pos = line_begin_pos;
	unsigned long begin_addr = read_hex_num(&line_pos, line_end_pos);
	++line_pos;
	unsigned long end_addr = read_hex_num(&line_pos, line_end_pos);
	++line_pos;
	char r = *line_pos++;
	char w = *line_pos++;
	char x = *line_pos++;
	char p __attribute__((unused)) = *line_pos++;

	/* Skip ourselves, but remember our load address. */
	void *expected_mapping_end = page_boundary_up(&etext);
	if ((const unsigned char *) end_addr >= (const unsigned char *) expected_mapping_end
		 && (const unsigned char *) begin_addr < (const unsigned char *) expected_mapping_end)
	{
		our_text_begin_address = (const void *) begin_addr;
		our_text_end_address = (const void *) end_addr;
		
		/* Compute our load address from the phdr p_vaddr of this segment.
		 * But how do we get at our phdrs?
		 * In general I think we need to hack the linker script to define a new symbol.
		 * But for now, just use the fact that it's very likely to be the lowest text addr. */
		our_load_address = (uintptr_t) our_text_begin_address;

		write_string("Skipping our own text mapping: ");
		write_ulong(begin_addr);
		write_string("-");
		write_ulong(end_addr);
		write_string("\n");
		
		return;
	}

	if (x == 'x')
	{
		if (w != 'w')
		{
			int ret = raw_mprotect((const void *) begin_addr,
				(const char *) end_addr - (const char *) begin_addr,
				PROT_READ | PROT_WRITE | PROT_EXEC);
			/* If we failed, it might be on the vdso page. */
			assert(ret == 0 || (signed long long) begin_addr < 0);
			if ((signed long long) begin_addr < 0)
			{
				write_string("Couldn't rewrite nor protect vdso mapping at ");
				write_ulong(begin_addr);
				write_string("\n");
				return;
			}
		}

		// it's executable; scan for syscall instructions
		unsigned char *begin_instr_pos = (unsigned char *) begin_addr;
		unsigned char *end_instr_pos = (unsigned char *) end_addr;
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
		 * We need to remember which sites we replaced.
		 * If we hit a ud2 that's not at such a site, we just do ud2.
		 */
		write_string("Scanning for syscall instructions within ");
		write_ulong(begin_addr);
		write_string("-");
		write_ulong(end_addr);
		write_string(" (");
		write_chars(line_begin_pos, line_end_pos);
		write_string(")\n");
		
		walk_instructions(begin_instr_pos, end_instr_pos, instruction_cb, NULL);
		/* Now check for in-betweens. */
		unsigned char *instr_pos = begin_instr_pos;
		while (instr_pos != end_instr_pos)
		{
			int syscall_instr_len = 0;
			if (0 != (syscall_instr_len = is_syscall_instr(instr_pos, end_instr_pos)))
			{
				instr_pos += syscall_instr_len;
			}
			else
			{
				++instr_pos;
			}
		}

		// restore original perms
		if (w != 'w')
		{
			int ret = raw_mprotect((const void *) begin_addr,
				(const char *) end_addr - (const char *) begin_addr,
				(r == 'r' ? PROT_READ : 0)
			|   (w == 'w' ? PROT_WRITE : 0)
			|   (x == 'x' ? PROT_EXEC : 0));
			assert(ret == 0);
		}
	}
}

void restore_rt(void); /* in restorer.s */
static void handle_sigill(int num);

_Bool __write_footprints;

#ifndef EXECUTABLE
#define RETURN_VALUE
static void __attribute__((constructor)) startup(void)
{
#else
#define RETURN_VALUE 0
static void *ignore_ud2_addr;
// scratch test code
int main(void)
{
#endif
	/* Is fd 7 open? If so, it's the input fd for our sanity check info
	 * from systemtap. */
	struct stat buf;
	int stat_ret = raw_fstat(7, &buf);
	if (stat_ret == 0)
	{
		write_string("File descriptor 7 is open; outputting systemtap cross-check info\n");

		/* PROBLEM: ideally we'd read in the stap script's output ourselves, and process
		 * it at every system call. But by reading in stuff from stap, we're doing more
		 * copying to/from userspace, so creating a feedback loop. This loop seems like
		 * it would blow up.
		 *
		 * Instead we write out what we think we touched, and do a diff outside the process.
		 * This also adds noise to stap's output, but without the feedback cycle: we ourselves
		 * won't read the extra output, hence won't write() more stuff in response.
		 */
		__write_footprints = 1;
	}
	else
	{
		write_string("File descriptor 7 is not open; skipping systemtap cross-check info\n");
	}
#if !defined(EXECUTABLE) && !defined(NDEBUG)
	write_string("In debug mode; pausing for five seconds\n");
	struct timespec tm = { /* seconds */ 5, /* nanoseconds */ 0 };
	raw_nanosleep(&tm, NULL);
#endif

	int fd = raw_open("/proc/self/maps", O_RDONLY);
	if (fd != -1)
	{
		// we use a simple buffer and a read loop
		char buf[8192];
		unsigned int ret;
		char *buf_pos = &buf[0]; // the next position to fill in the buffer
		char *entry_start_pos = &buf[0]; // the position
		size_t size_requested;
		do
		{
			// read some stuff, perhaps filling up the buffer
			size_requested = sizeof buf - (buf_pos - buf);
			ret = raw_read(fd, buf_pos, size_requested);
			char *buf_limit = buf_pos + ret;
			assert(buf_limit <= &buf[sizeof buf]);

			// we have zero or more complete entries in the buffer; iterate over them
			char *seek_pos;
			while (1)
			{
				seek_pos = entry_start_pos;
				// search forward for a newline
				while (seek_pos != buf_limit && *seek_pos != '\n')
				{ ++seek_pos; }

				// did we find one?
				if (seek_pos == buf_limit)
				{
					// no!
					// but we have a partial entry in the buffer
					// between entry_start_pos and seek_pos;
					// copy it to the start, re-set and continue
					__builtin_memmove(&buf[0], entry_start_pos, seek_pos - entry_start_pos);
					buf_pos = &buf[seek_pos - entry_start_pos];
					entry_start_pos = &buf[0];
					break;
				}
				else
				{
					assert(*seek_pos == '\n');
					// we have a complete entry; read it and advance entry_start_pos
					write_string("DEBUG: entry is: ");
					write_chars(entry_start_pos, seek_pos);
					write_string("\n");
					write_string("DEBUG: buffer is: ");
					write_chars(buf, buf_pos);
					write_string("\n");
					saw_mapping(entry_start_pos, seek_pos);
					entry_start_pos = seek_pos + 1;
					// if the newline was the last in the buffer, break and read more
					if (entry_start_pos == buf_pos + sizeof buf)
					{ buf_pos = entry_start_pos = &buf[0]; break; }

					// else we might have another entry; go round again
					continue;
				}
			}
		} while (ret > 0);
		raw_close(fd);
	}

	/* Install our SIGILL (was SIGTRAP, but that interferes with gdb) handler.
	 * Linux seems to require us to provide a restorer; the code is in restore_rt. */
	struct sigaction action = {
		//.sa_sigaction = &handle_sigtrap,
		.sa_handler = &handle_sigill,
		.sa_mask = 0,
		.sa_flags = /*SA_SIGINFO |*/ 0x04000000u /* SA_RESTORER */ | /*SA_RESTART |*/ SA_NODEFER,
		.sa_restorer = restore_rt
	};
	struct sigaction oldaction;
	raw_rt_sigaction(SIGILL, &action, &oldaction);

	/* Un-executablize our own code, except for the signal handler and the remainder of
	 * this function and those afterwards.
	 *
	 * For this, we need our load address. How can we get this? We've already seen it! */
	// long int len = &&exit_and_return - our_text_begin_address;
	// long int ret;
	// long int longprot = PROT_NONE;
	// long int op = SYS_mprotect;

	//	__asm__ (".align 4096");
exit_and_return:
	//__asm__ volatile ("movq %0, %%rdi      # \n\
	//		   movq %1, %%rsi      # \n\
	//		   movq %2, %%rdx      # \n\
	//		  "FIX_STACK_ALIGNMENT " \n\
	//		   movq %3, %%rax      # \n\
	//		   syscall	     # do the syscall \n\
	//		  "UNFIX_STACK_ALIGNMENT " \n"
	//  : /* no output*/ : "rm"(our_text_begin_address), "rm"(len), "rm"(longprot), "rm"(op) :  "%rax", "r12", SYSCALL_CLOBBER_LIST);

#ifdef EXECUTABLE
	// HACK for testing: do a ud2 right now!
	ignore_ud2_addr = &&ud2_addr;
ud2_addr:
	__asm__ ("ud2\n");

	// we must also exit without running any libdl exit handlers,
	// because we're an executable so our csu/startfiles include some cleanup
	// that will now cause traps (this isn't necessary in the shared library case)
	raw_exit(0);
#endif
	return RETURN_VALUE;
}

static void handle_sigill(int n)
{
	unsigned long *frame_base = __builtin_frame_address(0);
	struct ibcs_sigframe *p_frame = (struct ibcs_sigframe *) (frame_base + 1);

	/* Decode the syscall using sigcontext. */
	write_string("Took a trap from instruction at ");
	write_ulong((unsigned long) p_frame->uc.uc_mcontext.rip);
#ifdef EXECUTABLE
	if (p_frame->uc.uc_mcontext.rip == (uintptr_t) ignore_ud2_addr)
	{
		write_string(" which is our test trap address; continuing.\n");
		resume_from_sigframe(0, p_frame, 2);
		return;
	}
#endif
	write_string(" which we think is syscall number ");
	unsigned long syscall_num = (unsigned long) p_frame->uc.uc_mcontext.rax;
	write_ulong(syscall_num);
	write_string("\n");

	/* FIXME: check whether it creates executable mappings; if so,
	 * we make them nx, do the rewrite, then make them x. */

	struct generic_syscall gsp = {
		.saved_context = p_frame,
		.syscall_number = syscall_num,
		.arg0 = p_frame->uc.uc_mcontext.rdi,
		.arg1 = p_frame->uc.uc_mcontext.rsi,
		.arg2 = p_frame->uc.uc_mcontext.rdx,
		.arg3 = p_frame->uc.uc_mcontext.r10,
		.arg4 = p_frame->uc.uc_mcontext.r8,
		.arg5 = p_frame->uc.uc_mcontext.r9,
	};

	do_syscall_and_resume(&gsp); // inline
}
