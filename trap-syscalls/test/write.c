#define SYS_write 1
#define SYSCALL_CLOBBER_LIST \
	"%rdi", "%rsi", "%rax", "%rcx", "%rdx", "%r8", "%r9", "%r10", "%r11", \
	"%xmm0", "%xmm1", "%xmm2", "%xmm3", "%xmm4", "%xmm5", "%xmm6", "%xmm7", "%xmm8", \
	"%xmm9", "%xmm10", "%xmm11", "%xmm12", "%xmm13", "%xmm14", "%xmm15", \
	"cc" /*, "memory" */

static inline long int raw_write(int fd, const void *buf, long int count)
{
	long int ret;
	long int op = SYS_write;
	long int longfd = fd;
	__asm__ volatile ("movq %1, %%rdi      # \n\
	                   movq %2, %%rsi      # \n\
	                   movq %3, %%rdx      # \n\
	                   movq %4, %%rax      # \n\
	                   syscall             # do the syscall \n\
	                   movq %%rax, %0\n"
	  : "=r"(ret) : "rm"(longfd), "rm"(buf), "rm"(count), "rm"(op) : "r12",  SYSCALL_CLOBBER_LIST);

	return ret;
}

#define write_string(s) raw_write(1, (s), sizeof (s) - 1)

long int _start (void)
{
        long int ret = write_string("This is a test.\n");

        __asm__ volatile ("movq %0,    %%rdi \n\
                           movq $0x3c, %%rax \n\
                           syscall           \n"
        : /* No output */
        : "rm" (ret)
        : SYSCALL_CLOBBER_LIST);
}
