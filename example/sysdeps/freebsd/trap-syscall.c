#include <sys/syscall.h>
#include <sys/param.h>
#include <sys/user.h>
#include <sys/sysctl.h>
#include <sys/mman.h>

#include <assert.h> // assert

#include <stdio.h> // printf

#include <stdlib.h> // exit

#define KINFO_VMENTRY_BUFFER_SIZE 10000

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

#define write_string(s) raw_write(2, (s), sizeof (s) - 1)

static int is_syscall_instr(unsigned const char *p, unsigned const char *end)
{
	if ((end >= p + 2) && *p == 0x0f && *(p+1) == 0x05) return 2;
	return 0;
}

const char *fmt_hex_num(unsigned long n)
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

int __attribute__((noinline)) raw_getpid(void)
{
        long int ret;
        long int op = SYS_getpid;

        __asm__ volatile (FIX_STACK_ALIGNMENT " \n\
                          movq %[op], %%rax     \n\
                          syscall               \n\
                         "UNFIX_STACK_ALIGNMENT " \n\
                          movq %%rax, %[ret]    \n"
                        : [ret] "=r" (ret)
                        : [op]  "rm" (op)
                        : "r12", SYSCALL_CLOBBER_LIST);

        return ret;
}

int __attribute__((noinline)) raw_nanosleep(const struct timespec *rqtp,
                                         struct timespec *rmtp)
{
        long int ret;
        long int op = SYS_nanosleep;

        __asm__ volatile ("movq %[rqtp],        %%rdi   \n\
                           movq %[rmtp],        %%rsi   \n\
                          "FIX_STACK_ALIGNMENT "        \n\
                           movq %[op],          %%rax   \n\
                           syscall                      \n\
                          "UNFIX_STACK_ALIGNMENT "      \n\
                           movq %%rax,          %[ret]  \n"
                        : [ret]         "=r" (ret)
                        : [op]          "rm" (op)
                        , [rqtp]          "rm" (rqtp)
                        , [rmtp]         "rm" (rmtp)
                        : "r12", SYSCALL_CLOBBER_LIST);

        return ret;
}


int __attribute__((noinline)) raw_write(int fd,
                                        const void *buf, size_t nbytes)
{
        long int ret;
        long int op = SYS_write;

        __asm__ volatile ("movq %[fd],          %%rdi   \n\
                           movq %[buf],         %%rsi   \n\
                           movq %[nbytes],      %%rdx   \n\
                          "FIX_STACK_ALIGNMENT "        \n\
                           movq %[op],          %%rax   \n\
                           syscall                      \n\
                          "UNFIX_STACK_ALIGNMENT "      \n\
                           movq %%rax,          %[ret]  \n"
                        : [ret]         "=r" (ret)
                        : [op]          "rm" (op)
                        , [fd]          "rm" (fd)
                        , [buf]         "rm" (buf)
                        , [nbytes]      "rm" (nbytes)
                        : "r12", SYSCALL_CLOBBER_LIST);

        return ret;
}

int __attribute__((noinline)) raw_mprotect(const void *addr,
                                 size_t len, int prot)
{
        long int ret;
        long int op = SYS_mprotect;

        __asm__ volatile ("movq %[addr],        %%rdi   \n\
                           movq %[len],         %%rsi   \n\
                           movq %[prot],        %%rdx   \n\
                          "FIX_STACK_ALIGNMENT "        \n\
                           movq %[op],          %%rax   \n\
                           syscall                      \n\
                          "UNFIX_STACK_ALIGNMENT "      \n\
                           movq %%rax,          %[ret]  \n"
                        : [ret]         "=r" (ret)
                        : [op]          "rm" (op)
                        , [addr]        "rm" (addr)
                        , [len]         "rm" (len)
                        , [prot]        "rm" (prot)
                        : "r12", SYSCALL_CLOBBER_LIST);

        return ret;
}

int __attribute__((noinline)) raw_sigaction(int sig,
                                 const struct sigaction * restrict act,
                                 struct sigaction * restrict oact)
{
        long int ret;
        long int op = SYS_sigaction;

        __asm__ volatile ("movq %[sig],         %%rdi   \n\
                           movq %[act],         %%rsi   \n\
                           movq %[oact],        %%rdx   \n\
                          "FIX_STACK_ALIGNMENT "        \n\
                           movq %[op],          %%rax   \n\
                           syscall                      \n\
                          "UNFIX_STACK_ALIGNMENT "      \n\
                           movq %%rax,          %[ret]  \n"
                        : [ret]         "=r" (ret)
                        : [op]          "rm" (op)
                        , [sig]         "rm" (sig)
                        , [act]         "rm" (act)
                        , [oact]        "rm" (oact)
                        : "r12", SYSCALL_CLOBBER_LIST);

        return ret;
}


int __attribute__((noinline)) raw_sysctl(int *name, u_int namelen,
                                void *oldp, size_t *oldlenp,
                                void *newp, size_t newlen)
{
        long int ret;
        long int op = SYS___sysctl;

        __asm__ volatile ("movq %[name],         %%rdi  \n\
                           movq %[namelen],      %%rsi  \n\
                           movq %[oldp],         %%rdx  \n\
                           movq %[oldlenp],      %%r10  \n\
                           movq %[newp],         %%r8   \n\
                           movq %[newlen],       %%r9   \n\
                          "FIX_STACK_ALIGNMENT "        \n\
                           movq %[op],           %%rax  \n\
                           syscall                      \n\
                          "UNFIX_STACK_ALIGNMENT "      \n\
                           movq %%rax,           %[ret] \n"
                          : [ret]       "=r" (ret)
                          : [op]        "rm" (op)
                          , [name]      "rm" (name)
                          , [namelen]   "rm" (namelen)
                          , [oldp]      "rm" (oldp)
                          , [oldlenp]   "rm" (oldlenp)
                          , [newp]      "rm" (newp)
                          , [newlen]    "rm" (newlen)
                          : "r12", SYSCALL_CLOBBER_LIST);

        return ret;
}

int __attribute__((noinline)) raw_exit(int status)
{
        long int ret;
        long int op = SYS_exit;

        __asm__ volatile ("movq %[status],      %%rdi   \n\
                          "FIX_STACK_ALIGNMENT "        \n\
                           movq %[op],          %%rax   \n\
                           syscall                      \n\
                          "UNFIX_STACK_ALIGNMENT "      \n\
                           movq %%rax,          %[ret]  \n"
                        : [ret]         "=r" (ret)
                        : [op]          "rm" (op)
                        , [status]      "rm" (status)
                        : "r12", SYSCALL_CLOBBER_LIST);

        return ret;
}

/*
 * Fill the buffer passed in argument with information about the virtual
 * mappings of the current process, filling up to (*buflen) bytes.
 * (*buflen) is updated to reflect the actual number of bytes used.
 */
int get_vmmap(struct kinfo_vmentry *buf, size_t *buflen)
{
        int error, mib[4];
        size_t len = 0;

        pid_t pid = raw_getpid();

        // Set the request parameters for sysctl.
        mib[0] = CTL_KERN;
        mib[1] = KERN_PROC;
        mib[2] = KERN_PROC_VMMAP;
        mib[3] = pid;

        // Set len to reflect the size of the data.
        error = raw_sysctl(mib, 4, NULL, &len, NULL, 0);
        if (error) {
                return error;
        }

        if (len < *buflen) {
                *buflen = len;
        }

        // Fill buf.
        error = raw_sysctl(mib, 4, buf, buflen, NULL, 0);

        return error;
}

static inline int can_read  (int perm) { return (perm & 4) || 0; }
static inline int can_write (int perm) { return (perm & 2) || 0; }
static inline int can_exec  (int perm) { return (perm & 1) || 0; }

// This hack is intellectual property of Stephen Kell, for better
// or for worse.
static void replace_syscall_instructions(unsigned char *pos,
                                         unsigned char *end_pos)
{
        while (pos != end_pos)
        {
                int syscall_instr_len = 0;
                if (0 != (syscall_instr_len
                                        = is_syscall_instr(pos, end_pos))) {
                        write_string("Replacing syscall at ");
                        raw_write(2, fmt_hex_num((unsigned long) pos), 18);
                        write_string(" with trap.\n");

                        while (syscall_instr_len > 0)
                        {
                                // use UD2
                                if (syscall_instr_len == 2) {
                                        *pos++ = 0x0f;
                                } else if (syscall_instr_len == 1) {
                                        *pos++ = 0x0b;
                                }

                                --syscall_instr_len;
                        }
                }
                else
                {
                        ++pos;
                }
        }
}


static void dodge_permissions (struct kinfo_vmentry *kv)
{
        int r = can_read(kv->kve_protection);
        int w = can_write(kv->kve_protection);
        int x = can_exec(kv->kve_protection);

        // Make writeable if needed.
        if (!w) {
                int ret = raw_mprotect((const void *) kv->kve_start,
                                       kv->kve_end - kv->kve_start,
                                       PROT_READ | PROT_WRITE | PROT_EXEC);
                if (ret) {
                        write_string("Could not change permissions "
                                        "for segment ");
                        raw_write(2, fmt_hex_num(kv->kve_start), 18);
                        write_string("-");
                        raw_write(2, fmt_hex_num(kv->kve_end), 18);
                        write_string("; skipping.\n");
                        return;
                }
        }

        // Replace syscall instructions.

        unsigned char *pos = (unsigned char *) kv->kve_start;
        unsigned char *end_pos = (unsigned char *) kv->kve_end;
        replace_syscall_instructions(pos, end_pos);

        // Restore permissions if we changed them.
        if (!w) {
                int protections = (r ? PROT_READ  : 0)
                        | (w ? PROT_WRITE : 0)
                        | (x ? PROT_EXEC  : 0);
                int ret = raw_mprotect((const void *) kv->kve_start,
                                kv->kve_end - kv->kve_start,
                                protections);
                if (ret) {
                        write_string("Could not change permissions "
                                        "for segment ");
                        raw_write(2, fmt_hex_num(kv->kve_start), 18);
                        write_string("-");
                        raw_write(2, fmt_hex_num(kv->kve_end), 18);
                        write_string("; skipping.\n");
                        return;
                }
        }
}

static const void *our_text_begin_address;
static const void *our_text_end_address;

static void saw_mapping (struct kinfo_vmentry *kv)
{
        int x = can_exec(kv->kve_protection);

        (void) x;

        /*
         * If this is our text mapping,
         * skip it but remember our load address.
         */
        if (kv->kve_start <= (uint64_t) &raw_getpid
                        && kv->kve_end > (uint64_t) &raw_getpid) {
                our_text_begin_address = (const void *) kv->kve_start;
                our_text_end_address = (const void *) kv->kve_end;
                return;
        }

        if (x) {
                dodge_permissions(kv);
        }

        return;
}

static void handle_sigill(int num);

int main (void)
{
#if !defined(NDEBUG)
        write_string("In debug mode; pausing for five seconds\n");
        struct timespec tm = { /* seconds */ 5, /* nanoseconds */ 0 };
        raw_nanosleep(&tm, NULL);
#endif

        int error;
        static struct kinfo_vmentry buf[KINFO_VMENTRY_BUFFER_SIZE];
        uint8_t *bp, *eb;
        struct kinfo_vmentry *kv;

        size_t len = KINFO_VMENTRY_BUFFER_SIZE
                * sizeof (struct kinfo_vmentry);

        error = get_vmmap(buf, &len);

        if (error) {
                return error;
        }

        // Install our traps.
        for (bp = (uint8_t *) buf, eb = bp + len;
                        bp < eb;
                        bp += kv->kve_structsize) {
                kv = (struct kinfo_vmentry *)(uintptr_t) bp;
                saw_mapping(kv);

        }

        // Install the SIGILL handler.
        struct sigaction action = {
                .sa_handler = &handle_sigill,
                .sa_flags =  SA_RESTART
        };
        raw_sigaction(SIGILL, &action, 0);

        return 0;
}

static void /* __attribute__((optimize("O0"))) */ handle_sigill(int n)
{
        unsigned long entry_bp;
        __asm__("movq %%rbp, %0\n" : "=r" (entry_bp));

        /*
         * TODO: This has to be double-checked, to see if we really get
         * the correct p_frame and not garbage.
         */
        struct {
                __sighandler_t *sh;
                ucontext_t uc;
                siginfo_t info;
        } *p_frame = (void *) (entry_bp + 8);

        write_string("Took a trap from instruction at ");
        raw_write(2, fmt_hex_num(
                (unsigned long) p_frame->uc.uc_mcontext.mc_rip), 18);
        write_string(" which we think is syscall number ");
        unsigned long syscall_num =
                (unsigned long) p_frame->uc.uc_mcontext.mc_rax;
        raw_write(2, fmt_hex_num(syscall_num), 18);
        write_string("\n");

        /*
         * TODO
         * Handle the syscall, depending on the number.
         */
        if (syscall_num == 0) {
                write_string("Nosys. Continuing.\n");
        } else if (syscall_num == SYS_exit) {
                raw_exit(0);
        } else {
                write_string("Unknown syscall. Entering panic mode.\n");
                for (;;) ;
        }

        p_frame->uc.uc_mcontext.mc_rip += 2;

        (void) n;
        return;
}
