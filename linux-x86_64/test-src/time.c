#define SYS_exit 60
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
#define DO_EXIT_SYSCALL \
	long retcode = 0; \
	op = SYS_exit; \
	__asm__ volatile ("movq %0, %%rdi      # \n\
	                  "FIX_STACK_ALIGNMENT " \n\
	                   movq %1, %%rax      # \n\
	                   syscall             # do the syscall \n\
	                  "UNFIX_STACK_ALIGNMENT " \n" \
	  : /* no output*/ : "rm"(retcode), "rm"(op) : "r12", SYSCALL_CLOBBER_LIST);

void raw_exit(int status)
{
	long int op;
	DO_EXIT_SYSCALL;
}
typedef long time_t;

int _start (void) {
        time_t t;

        long int ret;

        __asm__ volatile (
         "movq $201,      %%rax  \n\
          movq _r_debug,  %%rdi  \n\
          movq %[addr_t], %%rdi  \n\
          syscall                \n\
          movq %%rax,     %[ret] \n"
          : [ret] "=r" (ret)
          : [addr_t] "rm" (&t)
          : SYSCALL_CLOBBER_LIST);

        raw_exit(ret);

        return 0;
}
