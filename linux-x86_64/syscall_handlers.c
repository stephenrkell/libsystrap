#include "do_syscall.h"
#include "syscall_handlers.h"
#include "raw_syscalls.h"

#define PERFORM_SYSCALL             \
          FIX_STACK_ALIGNMENT "   \n\
          movq %[op], %%rax       \n\
          syscall                 \n\
         "UNFIX_STACK_ALIGNMENT " \n\
          movq %%rax, %[ret]      \n"

/*
 * The x86-64 syscall argument passing convention goes like this:
 * RAX: syscall_number
 * RDI: ARG0
 * RSI: ARG1
 * RDX: ARG2
 * R10: ARG3
 * R8:  ARG4
 * R9:  ARG5
 */
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

#ifdef DUMP_SYSCALLS
        write_string("Passing arguments:              ");
        raw_write(2, fmt_hex_num(gsp->arg0), 18);
        write_string("\n");
#endif

        __asm__ volatile ("movq %[arg0], %%rdi \n"
                           PERFORM_SYSCALL
          : [ret]  "=r" (ret)
          : [op]   "rm" ((long int) gsp->syscall_number)
          , [arg0] "rm" ((long int) gsp->arg0)
          : "r12", SYSCALL_CLOBBER_LIST);

        return ret;
}

long int __attribute__((noinline)) do_syscall3 (struct generic_syscall *gsp)
{
        long int ret;
        __asm__ volatile ("movq %[arg0], %%rdi \n\
                           movq %[arg1], %%rsi \n\
                           movq %[arg2], %%rdx \n"
                           PERFORM_SYSCALL
          : [ret]  "=r" (ret)
          : [op]   "rm" ((long int) gsp->syscall_number)
          , [arg0] "rm" ((long int) gsp->arg0)
          , [arg1] "rm" ((long int) gsp->arg1)
          , [arg2] "rm" ((long int) gsp->arg2)
          : "r12", SYSCALL_CLOBBER_LIST);

        return ret;
}

/*
 * Here comes do_syscallN for N <- [2..5]
 */

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
static long int do_exit (struct generic_syscall *gsp)
{
        return do_syscall1(gsp);
}

static long int do_getpid (struct generic_syscall *gsp)
{
        return do_syscall0(gsp);
}

static long int do_time (struct generic_syscall *gsp)
{
        long int ret;
        time_t *old_arg0 = (time_t *) gsp->arg0;

        if (old_arg0) {
                // Save the address, replace it with own.
                time_t tmp;
                gsp->arg0 = (long int) &tmp;
        }

       ret = do_syscall1(gsp);

        if (old_arg0) {

                *old_arg0 = (time_t) *((time_t *)gsp->arg0);
                gsp->arg0 = (long int) old_arg0;
        }
        return ret;
}

static long int do_write (struct generic_syscall *gsp)
{
        return do_syscall3(gsp);
}

static long int do_read (struct generic_syscall *gsp)
{
        /*
         * XXX What we should really do here is remap the buffer via
         * malloc(), but we don’t have a malloc yet.
         */
        return do_syscall3(gsp);
}

long int (*syscalls[SYSCALL_MAX])(struct generic_syscall *) = {
        DECL_SYSCALL(read)
        DECL_SYSCALL(write)
        DECL_SYSCALL(getpid)
        DECL_SYSCALL(exit)
        DECL_SYSCALL(time)
};
