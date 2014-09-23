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
 *        YES, but must read using raw syscalls.
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
#include <asm/sigcontext.h>
#include <asm/siginfo.h>
#include <asm/ucontext.h>
// #include <ucontext.h>
#include <sys/syscall.h>
// #include <sys/types.h>
// #include <sys/stat.h>
// #include <fcntl.h>
#include <asm/fcntl.h>
#include <sys/mman.h>
#include <stdint.h>

#include "trap-syscalls.h"
#include "raw-syscalls.h"
#include "do-syscall.h"

/* If we build a standalone executable, we include a test trap. */
#ifdef EXECUTABLE
static void *ignore_ud2_addr;
#endif

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

static void saw_mapping(const char *pos, const char *end)
{
	unsigned long begin_addr = read_hex_num(&pos, end);
	++pos;
	unsigned long end_addr = read_hex_num(&pos, end);
	++pos;
	char r = *pos++;
	char w = *pos++;
	char x = *pos++;
	char p = *pos++;


	/* If this is our text mapping, skip it but remember our load address. */
	if ((const unsigned char *) begin_addr <= (const unsigned char *) &raw_open
			&& (const unsigned char *) end_addr > (const unsigned char *) &raw_open)
	{
		our_text_begin_address = (const void *) begin_addr;
		our_text_end_address = (const void *) end_addr;
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
				raw_write(2, fmt_hex_num(begin_addr), 18);
				write_string("\n");
				return;
			}
		}

		// it's executable; scan for syscall instructions
		unsigned char *pos = (unsigned char *) begin_addr;
		unsigned char *end_pos = (unsigned char *) end_addr;
		while (pos != end_pos)
		{
			int syscall_instr_len = 0;
			if (0 != (syscall_instr_len = is_syscall_instr(pos, end_pos)))
			{
				write_string("Replacing syscall at ");
				raw_write(2, fmt_hex_num((unsigned long) pos), 18);
				write_string(" with trap.\n");

				while (syscall_instr_len > 0)
				{
					//if (syscall_instr_len == 1) *pos++ = 0xcc;
					//else *pos++ = 0x90;
					// use UD2
					if (syscall_instr_len == 2) *pos++ = 0x0f;
					else if (syscall_instr_len == 1) *pos++ = 0x0b;

					--syscall_instr_len;
				}
			}
			else
			{
				++pos;
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
					unsigned i;
					for (i = 0; i < seek_pos - entry_start_pos; ++i)
					{
						buf[i] = buf[(entry_start_pos - buf) + i];
					}
					buf_pos = &buf[i];
					entry_start_pos = &buf[0];
					break;
				}
				// else yes
				// assert(*seek_pos == '\n');
				// we have a complete entry; read it and advance entry_start_pos
				saw_mapping(entry_start_pos, seek_pos);
				entry_start_pos = seek_pos + 1;
				// if the newline was the last in the buffer, break and read more
				if (entry_start_pos == buf_pos + sizeof buf)
				{ buf_pos = entry_start_pos = &buf[0]; break; }

				// else we might have another entry; go round again
				continue;
			}
		} while (ret == size_requested);
		raw_close(fd);
	}

	/* Install our SIGILL (was SIGTRAP, but that interferes with gdb) handler.
	 * Linux seems to require us to provide a restorer; the code is inlined
	 * at the bottom of this function. */
	struct sigaction action = {
		//.sa_sigaction = &handle_sigtrap,
		.sa_handler = &handle_sigill,
		.sa_mask = 0,
		.sa_flags = /*SA_SIGINFO |*/ 0x04000000u /* SA_RESTORER */ | SA_RESTART,
		.sa_restorer = restore_rt
	};
	struct sigaction oldaction;
	raw_rt_sigaction(SIGILL, &action, &oldaction);

	/* Un-executablize our own code, excpet for the signal handler and the remainder of
	 * this function and those afterwards.
	 *
	 * For this, we need our load address. How can we get this? We've already seen it! */
	long int len = &&exit_and_return - our_text_begin_address;
	long int ret;
	long int longprot = PROT_NONE;
	long int op = SYS_mprotect;


        //	__asm__ (".align 4096");
exit_and_return:
	//__asm__ volatile ("movq %0, %%rdi      # \n\
	//                   movq %1, %%rsi      # \n\
	//                   movq %2, %%rdx      # \n\
	//                  "FIX_STACK_ALIGNMENT " \n\
	//                   movq %3, %%rax      # \n\
	//                   syscall             # do the syscall \n\
	//                  "UNFIX_STACK_ALIGNMENT " \n"
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

static void  __attribute__((optimize("O0"))) handle_sigill(int n)
{
	/* HACK: force -O0 because getting the right break pointer is really important. */
	unsigned long entry_bp;
	__asm__("movq %%rbp, %0\n" : "=r"(entry_bp));

	/* In kernel-speak this is a "struct sigframe" / "struct rt_sigframe" --
	 * sadly no user-level header defines it. But it seems to be vaguely standard
	 * per-architecture (here Intel iBCS). */
	struct
	{
		char *pretcode;
		struct ucontext uc;
		struct siginfo info;
	} *p_frame = (void*) (entry_bp + 8);

	/* Decode the syscall using sigcontext. */
	write_string("Took a trap from instruction at ");
	raw_write(2, fmt_hex_num((unsigned long) p_frame->uc.uc_mcontext.rip), 18);
#ifdef EXECUTABLE
	if (p_frame->uc.uc_mcontext.rip == (uintptr_t) ignore_ud2_addr)
	{
		write_string(" which is our test trap address; continuing.\n");
		goto out;
	}
#endif
	write_string(" which we think is syscall number ");
	unsigned long syscall_num = (unsigned long) p_frame->uc.uc_mcontext.rax;
	raw_write(2, fmt_hex_num(syscall_num), 18);
	write_string("\n");

	/* Check whether it creates executable mappings; if so,
	 * we make them nx, do the rewrite, then make them x. */

        struct generic_syscall gs
                = { .syscall_number = syscall_num,
                    .arg0 = p_frame->uc.uc_mcontext.rdi,
                    .arg1 = p_frame->uc.uc_mcontext.rsi,
                    .arg2 = p_frame->uc.uc_mcontext.rdx,
                    .arg3 = p_frame->uc.uc_mcontext.r10,
                    .arg4 = p_frame->uc.uc_mcontext.r8,
                    .arg5 = p_frame->uc.uc_mcontext.r9};

        long int ret = do_syscall((struct syscall *) &gs);

        /* Set the return value of the emulated syscall */
        p_frame->uc.uc_mcontext.rax = ret;

	/* Resume from *after* the faulting instruction. */
out:
	// adjust the saved program counter to point past the trapping instr
	p_frame->uc.uc_mcontext.rip += 2;
	// this doesn't work if you specify a restorer! because pretcode points there
	// p_frame->pretcode += 2;
	return;
}
