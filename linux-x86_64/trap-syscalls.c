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

/* Our callee-save registers are 
 *         rbp, rbx, r12, r13, r14, r15
 * but all others need to be in the clobber list.
 *         rdi, rsi, rax, rcx, rdx, r8, r9, r10, r11
 *         xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15
 *         condition codes, memory
 */
#define SYSCALL_CLOBBER_LIST \
	"%rdi", "%rsi", "%rax", "%rcx", "%rdx", "%r8", "%r9", "%r10", "%r11", \
	"%xmm0", "%xmm1", "%xmm2", "%xmm3", "%xmm4", "%xmm5", "%xmm6", "%xmm7", "%xmm8", \
	"%xmm9", "%xmm10", "%xmm11", "%xmm12", "%xmm13", "%xmm14", "%xmm15", \
	"cc" /*, "memory" */
#define FIX_STACK_ALIGNMENT \
	"movq %%rsp, %%rax\n\
	 andq $0xf, %%rax    # now we have either 8 or 0 in rax \n\
	 subq %%rax, %%rsp   # fix the stack pointer \n\
	 movq %%rax, %%r12   # save the amount we fixed it up by in r12 \n\
	 "

#define UNFIX_STACK_ALIGNMENT \
	"addq %%r12, %%rsp\n"
	
/* If we build a standalone executable, we include a test trap. */
#ifdef EXECUTABLE
static void *ignore_ud2_addr;
#endif

#define DO_EXIT_SYSCALL \
	long retcode = 0; \
	op = SYS_exit; \
	__asm__ volatile ("movq %0, %%rdi      # \n\
	                  "FIX_STACK_ALIGNMENT " \n\
	                   movq %1, %%rax      # \n\
	                   syscall             # do the syscall \n\
	                  "UNFIX_STACK_ALIGNMENT " \n" \
	  : /* no output*/ : "rm"(retcode), "rm"(op) : "r12", SYSCALL_CLOBBER_LIST);

static void raw_exit(int status)
{
	long int op;
	DO_EXIT_SYSCALL;
}

static int __attribute__((noinline)) raw_open(const char *pathname, int flags)
{
	long int ret;
	long int op = SYS_open;
	long int longflags = flags;
	
	/* We have to do it all in one big asm statement, since the compiler 
	 * can change what's in registers in between asm statements. */
	__asm__ volatile ("movq %1, %%rdi      # \n\
	                   movq %2, %%rsi      # \n\
	                  "FIX_STACK_ALIGNMENT " \n\
	                   movq %3, %%rax      # \n\
	                   syscall             # do the syscall \n\
	                  "UNFIX_STACK_ALIGNMENT " \n\
	                   movq %%rax, %0\n"
	  : "=r"(ret) : "rm"(pathname), "rm"(longflags), "rm"(op) : "r12", SYSCALL_CLOBBER_LIST);
	return ret;
}

static int __attribute__((noinline)) raw_nanosleep(struct timespec *req, 
			struct timespec *rem)
{
	long int ret;
	long int op = SYS_nanosleep;
	
	/* We have to do it all in one big asm statement, since the compiler 
	 * can change what's in registers in between asm statements. */
	__asm__ volatile ("movq %1, %%rdi      # \n\
	                   movq %2, %%rsi      # \n\
	                  "FIX_STACK_ALIGNMENT " \n\
	                   movq %3, %%rax      # \n\
	                   syscall             # do the syscall \n\
	                  "UNFIX_STACK_ALIGNMENT " \n\
	                   movq %%rax, %0\n"
	  : "=r"(ret) : "rm"(req), "rm"(rem), "rm"(op) : "r12", SYSCALL_CLOBBER_LIST);
	return ret;
}

static int __attribute__((noinline)) raw_read(int fd, void *buf, size_t count)
{
	long int ret;
	long int op = SYS_read;
	long int longfd = fd;
	__asm__ volatile ("movq %1, %%rdi      # \n\
	                   movq %2, %%rsi      # \n\
	                   movq %3, %%rdx      # \n\
	                  "FIX_STACK_ALIGNMENT " \n\
	                   movq %4, %%rax      # \n\
	                   syscall             # do the syscall \n\
	                  "UNFIX_STACK_ALIGNMENT " \n\
	                   movq %%rax, %0\n"
	  : "=r"(ret) : "rm"(longfd), "rm"(buf), "rm"(count), "rm"(op) : "r12",  SYSCALL_CLOBBER_LIST);

	return ret;
}

static ssize_t __attribute__((noinline)) raw_write(int fd, const void *buf, size_t count);

static int __attribute__((noinline)) raw_close(int fd)
{
	long int ret;
	long int op = SYS_close;
	long int longfd = fd;
	__asm__ volatile ("movq %1, %%rdi      # \n\
	                  "FIX_STACK_ALIGNMENT " \n\
	                   movq %2, %%rax      # \n\
	                   syscall             # do the syscall \n\
	                  "UNFIX_STACK_ALIGNMENT " \n\
	                   movq %%rax, %0\n"
	  : "=r"(ret) : "rm"(longfd), "rm"(op) : "%r12", SYSCALL_CLOBBER_LIST);
	return ret;
}

static int __attribute__((noinline)) raw_mprotect(const void *addr, size_t len, int prot)
{
	long int ret;
	long int op = SYS_mprotect;
	long int longprot = prot;
	__asm__ volatile ("movq %1, %%rdi      # \n\
	                   movq %2, %%rsi      # \n\
	                   movq %3, %%rdx      # \n\
	                  "FIX_STACK_ALIGNMENT " \n\
	                   movq %4, %%rax      # \n\
	                   syscall             # do the syscall \n\
	                  "UNFIX_STACK_ALIGNMENT " \n\
	                   movq %%rax, %0\n"
	  : "=r"(ret) : "rm"(addr), "rm"(len), "rm"(longprot), "rm"(op) : "r12",  SYSCALL_CLOBBER_LIST);
	return ret;
}

static int __attribute__((noinline)) raw_rt_sigaction(int signum, const struct sigaction *act,
                     struct sigaction *oldact)
{
	long int ret;
	long int op = SYS_rt_sigaction;
	long int longsignum = signum;
	size_t sigsetsize = sizeof (sigset_t);
	__asm__ volatile ("movq %1, %%rdi      # \n\
	                   movq %2, %%rsi      # \n\
	                   movq %3, %%rdx      # \n\
	                   movq %4, %%r10      # \n\
	                  "FIX_STACK_ALIGNMENT " \n\
	                   movq %5, %%rax      # \n\
	                   syscall             # do the syscall \n\
	                  "UNFIX_STACK_ALIGNMENT " \n\
	                   movq %%rax, %0\n"
	  : "=r"(ret) : "rm"(longsignum), "rm"(act), "rm"(oldact), "rm"(sigsetsize), "rm"(op) : "r12",  SYSCALL_CLOBBER_LIST);

	return ret;
}

static void assert_fail(const char *msg)
{
	long strlen = 0;
	const char *msg_end = msg;
	while (*msg_end++);
	raw_write(2, msg, msg_end - msg - 1);
	raw_exit(128 + /* SIGABRT */ 6);
}

#define stringify(cond) #cond

#define assert(cond) \
	do { ((cond) ? ((void) 0) : (assert_fail("Assertion failed: \"" stringify((cond)) "\", file " __FILE__ ))); }  while (0)

static int is_syscall_instr(const char *p, const char *end)
{
	if ((end >= p + 2) && *p == 0x0f && *(p+1) == 0x05) return 2;
	return 0;
}

static unsigned long read_hex_num(const char **p_c, const char *end)
{
	unsigned long cur = 0;
	while (*p_c != end && (**p_c >= '0' && **p_c <= '9') || (**p_c >= 'a' && **p_c <= '\f'))
	{
		cur <<= 4;
		cur += ((**p_c >= '0' && **p_c <= '9') ? **p_c - '0'
				 : 10 + **p_c - 'a');
		++(*p_c);
	}
	return cur;
}
static const char *fmt_hex_num(unsigned long n);

static const void *our_text_begin_address;
static const void *our_text_end_address;

#define write_string(s) raw_write(2, (s), sizeof (s) - 1)

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
			assert(ret == 0);
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

static void handle_sigill(int num);

#ifndef EXECUTABLE
static void __attribute__((constructor)) startup(void) 
{
#else
static void *ignore_ud2_addr;
// scratch test code
int main(void)
{
#endif

#if !defined(EXECUTABLE) && !defined(NDEBUG)
	write_string("In debug mode; pausing for five seconds\n");
	struct timespec tm = { /* seconds */ 5, /* nanoseconds */ 0 };
	raw_nanosleep(&tm, NULL);
#endif
	
	int fd = raw_open("/proc/self/maps", O_RDONLY);
	if (fd != -1)
	{
		// we use a circular buffer and a read loop
		char buf[8192];
		int ret;
		char *buf_pos = &buf[0];         // the next character to be written
		char *entry_start_pos = &buf[0]; // the position
		size_t size_requested;
		do
		{
			// read some stuff, perhaps filling up the buffer
			size_requested = sizeof buf - (buf_pos - buf);
			ret = raw_read(fd, buf_pos, size_requested);
			buf_pos += ret;
			// if we filled up the buffer, wrap around
			if (buf_pos == buf + sizeof buf) buf_pos = &buf[0];
			// do we have a complete entry yet?
			char *seek_pos = entry_start_pos;
			do
			{	
				while (seek_pos != buf_pos && seek_pos != buf + sizeof buf && *seek_pos != '\n')
				{ ++seek_pos; }
				if (seek_pos == buf_pos) break; // we need to read more
			} while (seek_pos == buf + sizeof buf);  // wrap around 
					
			if (*seek_pos == '\n')
			{
				// we have a complete entry; read it and advance entry_start_pos
				saw_mapping(entry_start_pos, seek_pos);
				entry_start_pos = seek_pos + 1;
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
		.sa_restorer = &&restore_rt
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
	
	__asm__ (".align 4096");
exit_and_return:
	__asm__ volatile ("movq %0, %%rdi      # \n\
	                   movq %1, %%rsi      # \n\
	                   movq %2, %%rdx      # \n\
	                  "FIX_STACK_ALIGNMENT " \n\
	                   movq %3, %%rax      # \n\
	                   syscall             # do the syscall \n\
	                  "UNFIX_STACK_ALIGNMENT " \n"
	  : /* no output*/ : "rm"(our_text_begin_address), "rm"(len), "rm"(longprot), "rm"(op) :  "%rax", "r12", SYSCALL_CLOBBER_LIST);

#ifdef EXECUTABLE
	// HACK for testing: do a ud2 right now!
	ignore_ud2_addr = &&ud2_addr;
ud2_addr:
	__asm__ ("ud2\n");

	// we must also exit without running any libdl exit handlers,
	// because we're an executable so our csu/startfiles include some cleanup
	// that will now cause traps (this isn't necessary in the shared library case)
	DO_EXIT_SYSCALL
#endif
	goto out;
restore_rt:
	/* do the "retun from signal handler" (sigret) syscall */
	asm("movq $0xf, %rax\n\
		 syscall");
out:
	return;
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
	
	/* Otherwise run the syscall directly. */
	if (syscall_num == SYS_exit)
	{
		long retcode = /* what was in rdi? */(unsigned long) p_frame->uc.uc_mcontext.rdi;
		long op = SYS_exit;
		__asm__ volatile ("movq %0, %%rdi      # \n\
		                  "FIX_STACK_ALIGNMENT " \n\
		                   movq %1, %%rax      # \n\
		                   syscall             # do the syscall \n\
		                  "UNFIX_STACK_ALIGNMENT " \n"
		  : /* no output*/ : "rm"(retcode), "rm"(op) : "r12", SYSCALL_CLOBBER_LIST);
	}
	
	/* Resume from *after* the faulting instruction. */
out: 
	// this doesn't work!
	p_frame->uc.uc_mcontext.rip += 2;
	// this does!
	p_frame->pretcode += 2;
	return;
}

static ssize_t __attribute__((noinline)) raw_write(int fd, const void *buf, size_t count)
{
	long int ret;
	long int op = SYS_write;
	long int longfd = fd;
	__asm__ volatile ("movq %1, %%rdi      # \n\
	                   movq %2, %%rsi      # \n\
	                   movq %3, %%rdx      # \n\
	                  "FIX_STACK_ALIGNMENT " \n\
	                   movq %4, %%rax      # \n\
	                   syscall             # do the syscall \n\
	                  "UNFIX_STACK_ALIGNMENT " \n\
	                   movq %%rax, %0\n"
	  : "=r"(ret) : "rm"(longfd), "rm"(buf), "rm"(count), "rm"(op) : "r12",  SYSCALL_CLOBBER_LIST);

	return ret;
}
static const char *fmt_hex_num(unsigned long n)
{
	static char buf[19];
	buf[0] = '0';
	buf[1] = 'x';
	signed i_dig = 15;
	do
	{
		unsigned long dig = (n >> (4 * i_dig)) & 0xf;
		buf[2 + 15 - i_dig] = (dig > 9) ? ('a' + dig - 10) : ('0' + dig);
		--i_dig;
	} while (i_dig >= 0);
	buf[18] = '\0';
	return buf;
}
