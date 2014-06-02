#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>

#ifndef USE_RAW_SIGACTION
#include <ucontext.h>
#else
#include <asm/signal.h>
#include <asm/siginfo.h>
#endif

#ifndef USE_RAW_SIGACTION
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#else
#include <asm/fcntl.h>
#endif

#include <sys/mman.h>

#ifndef USE_RAW_SIGACTION
#include <assert.h>
#include <stdlib.h>
#else
static void raw_exit(int);
#define exit raw_exit
#define assert(c) ((c) ? (void)0 : raw_exit(128 + 6))
#endif

static void  __attribute__((optimize("O0"))) handle_sigill(int n)
{
	unsigned long entry_sp;
	__asm__("movq %%rsp, %0\n" : "=r"(entry_sp));
	
	struct 
	{
		char *pretcode;
		struct ucontext uc;
		struct siginfo info;
	} *p_frame = (void*) (entry_sp + 8);
	
	exit(0);
}

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

static void raw_exit(int status)
{
	long retcode = status;
	long op = SYS_exit;
	__asm__ volatile ("movq %0, %%rdi      # \n\
	                  "FIX_STACK_ALIGNMENT " \n\
	                   movq %1, %%rax      # \n\
	                   syscall             # do the syscall \n\
	                  "UNFIX_STACK_ALIGNMENT " \n"
	  : /* no output*/ : "rm"(retcode), "rm"(op) : "r12", SYSCALL_CLOBBER_LIST);
}

static int __attribute__((noinline)) raw_rt_sigaction(int signum, const struct sigaction *act,
                     struct sigaction *oldact)
{
	long int ret;
	long int op = SYS_rt_sigaction;
	long int longsignum = signum;
	size_t sigsetsize = 8; //sizeof (sigset_t);
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

int main(void)
{
	struct sigaction sa = {
		//.sa_handler = &handle_sigill,
#ifndef USE_RAW_SIGACTION
		.sa_sigaction = &handle_sigill_long
#else
		.sa_handler = &handle_sigill_long
#endif
				,
		.sa_flags = 0x04000000u /* SA_RESTORER */,
		.sa_restorer = &&restore_rt
	}, old_sa;
	int ret = 
#ifndef USE_RAW_SIGACTION
			sigaction(SIGILL, &sa, &old_sa);
#else
			raw_rt_sigaction(SIGILL, &sa, &old_sa);
#endif
	assert(ret == 0);

	asm("ud2");
	goto out;
restore_rt:
	asm("mov $0xf, %rax\n\
		 syscall");
out:
	
	return 0;
}
