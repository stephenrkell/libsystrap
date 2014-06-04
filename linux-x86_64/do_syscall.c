#include <unistd.h>
#include <sys/time.h>

#include "do_syscall.h"

#define PERFORM_SYSCALL \
          FIX_STACK_ALIGNMENT "   \n\
          movq %[ret], %%rax      \n\
          syscall                 \n\
         "UNFIX_STACK_ALIGNMENT " \n\
          movq %%rax, %[op]       \n"

#define SYSCALL_CLOBBER_LIST \
  "%rdi", "%rsi", "%rax", "%rcx", "%rdx", "%r8", "%r9", "%r10", "%r11", \
  "%xmm0", "%xmm1", "%xmm2", "%xmm3", "%xmm4", "%xmm5", "%xmm6", "%xmm7", "%xmm8", \
  "%xmm9", "%xmm10", "%xmm11", "%xmm12", "%xmm13", "%xmm14", "%xmm15", \
  "cc"
#define FIX_STACK_ALIGNMENT \
         "movq %%rsp, %%rax\n\
          andq $0xf, %%rax    # now we have either 8 or 0 in rax \n\
          subq %%rax, %%rsp   # fix the stack pointer \n\
          movq %%rax, %%r12   # save the amount we fixed it up by in r12 \n\
          "
#define UNFIX_STACK_ALIGNMENT \
        "addq %%r12, %%rsp\n"

long int __attribute__((noinline)) do_syscall0 (struct generic_syscall *gsp)
{
        long int ret;
        __asm__ volatile (PERFORM_SYSCALL
          : [ret] "=r" (ret)
          : [op]  "rm" ((long int) gsp->syscall_number)
          : "r12", SYSCALL_CLOBBER_LIST);

        return ret;
}

long int __attribute__((noinline)) do_syscall1 (struct generic_syscall *gsp)
{
        long int ret;
        __asm__ volatile ("movq %[arg0], %%rdi \n"
                           PERFORM_SYSCALL
          : [ret]  "=r" (ret)
          : [op]   "rm" ((long int) gsp->syscall_number)
          , [arg0] "rm" ((long int) gsp->arg0)
          : "r12", SYSCALL_CLOBBER_LIST);

        return ret;
}

long int __attribute__((noinline)) do_syscall6 (struct generic_syscall *gsp)
{
        long int ret;
        __asm__ volatile ("movq %[arg0], %%rdi \n\
                           movq %[arg1], %%rsi \n\
                           movq %[arg2], %%rdx \n\
                           movq %[arg3], %%r10 \n\
                           movq %[arg4], %%r8  \n\
                           movq %[arg5], %%r9  \n"
                           PERFORM_SYSCALL
          : [ret]  "=r" (ret)
          : [op]   "rm" ((long int) gsp->syscall_number)
          , [arg0] "rm" ((long int) gsp->arg0)
          , [arg1] "rm" ((long int) gsp->arg1)
          , [arg2] "rm" ((long int) gsp->arg2)
          , [arg3] "rm" ((long int) gsp->arg3)
          , [arg4] "rm" ((long int) gsp->arg4)
          , [arg5] "rm" ((long int) gsp->arg5)
          : "r12", SYSCALL_CLOBBER_LIST);

        return ret;
}

long int do_syscall (struct syscall *sys)
{
        struct generic_syscall *gsp = (struct generic_syscall *) sys;
        long ret = -1;
        switch (sys->syscall_number) {
                case SYS_exit:
                        do_syscall1(gsp);
                        break;
                default:
                        panic();
        }

        return ret;
}
