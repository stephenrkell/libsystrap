#define SYSCALL_CLOBBER_LIST \
	"%rdi", "%rsi", "%rax", "%rcx", "%rdx", "%r8", "%r9", "%r10", "%r11", \
	"%xmm0", "%xmm1", "%xmm2", "%xmm3", "%xmm4", "%xmm5", "%xmm6", "%xmm7", "%xmm8", \
	"%xmm9", "%xmm10", "%xmm11", "%xmm12", "%xmm13", "%xmm14", "%xmm15", \
	"cc" /*, "memory" */
int _start (void)
{
        char *f = "test-src/shakespeare.txt";
        char tab[10] = {0};

        long int ret;

        asm volatile ("movq %[f],   %%rdi \n\
                       movq $0x0,   %%rsi \n\
                       movq $0x0,   %%rdx \n\
                       movq $0x2,   %%rax  \n\
                       syscall             \n\
                       movq %%rax,  %%rdi  \n\
                       movq %[tab], %%rsi  \n\
                       movq $0x5,   %%rdx  \n\
                       movq $0x0,   %%rax  \n\
                       syscall             \n\
                       movq %%rax,  %[ret] \n"
         : [ret]   "=r" (ret)
         : [f]     "rm" (f)
         , [tab]   "rm" (tab)
         :SYSCALL_CLOBBER_LIST);

        asm volatile ("movq %[ret], %%rdi \n\
                       movq $60,    %%rax \n\
                       syscall            \n"
                       : /* no output */
                       : [ret] "rm" (ret)
                       :);
}
