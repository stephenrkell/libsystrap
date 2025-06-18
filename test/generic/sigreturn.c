/* Take care to snarf the kernel, not libc, definitions of various structs.
 * We will link against libsystrap, for its raw_* syscall wrappers, not a libc. */
#include <stddef.h>
#include "../../include/raw-syscalls-impl.h"

/* Like other test cases in here, to keep ourselves minimal, we avoid
 * linking to a libc. That means we have to jump through some hoops to
 * tell the kernel about our sigframe restorer -- the libc signal/sigaction
 * functions would normally do this. We link in restorer.o from the main
 * libsystrap tree so that we definitely have the restorer code in our
 * binary, despite our libc-lessness.
 */

signed long write(int fd, const void *buf, size_t count);
int getpid(void);
int kill(int pid, int sig);
void abort(void) __attribute__((noreturn));

static void handle_it(int signum)
{
	static const char msg[] = "Got SIGUSR1! Resuming...\n";
	raw_write(2, msg, sizeof msg);
}

void _start(void)
{
	struct __asm_sigaction test = { .sa_handler = handle_it, .sa_restorer = &__restore_rt,
		.sa_flags = SA_RESTORER | SA_NODEFER };
	int ret = raw_rt_sigaction(SIGUSR1, &test, NULL);
	if (ret != 0) raw_exit(128 + SIGABRT);

	int mypid = raw_getpid();
	raw_kill(mypid, SIGUSR1);

	raw_exit(0);
}
