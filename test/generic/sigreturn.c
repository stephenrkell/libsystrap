/* To allow access to the ibcs_sigframe, we don't include (m)any standard
 * headers in this file, only our own headers that take care to snarf the
 * kernel, not libc, definitions of various structs. */
#include <stddef.h>
#include "../../include/raw-syscalls-impl.h"

/* Like other test cases in here, to keep ourselves minimal, we avoid
 * linking to a libc. That is a problem because it means we have no
 * restorer, so the kernel will put a bogus value on the stack. Or
 * maybe the whole sigframe will be misaligned? Not sure. Let's try
 * linking our own restorer. Since we haven't used sigaction() to
 * inform the kernel about the restorer, we manually set the signal
 * frame's pretcode field to point to the restorer. */

signed long write(int fd, const void *buf, size_t count);
typedef void (*sighandler_t)(int);
sighandler_t signal(int signum, sighandler_t handler);
int getpid(void);
int kill(int pid, int sig);
void abort(void) __attribute__((noreturn));

#include <errno.h>

static void handle_it(int signum)
{
	unsigned long *frame_base = __builtin_frame_address(0);
    struct ibcs_sigframe *p_frame = (struct ibcs_sigframe *) (frame_base + 1);
	p_frame->pretcode = &__restore_rt;

	static const char msg[] = "Got SIGUSR1! Resuming...\n";
	write(2, msg, sizeof msg);
}

void _start(void)
{
	errno = 0;
	signal(SIGUSR1, handle_it);
	if (errno != 0) abort();

	int mypid = getpid();
	kill(mypid, SIGUSR1);

	exit(0);
}
