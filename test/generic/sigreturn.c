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
	struct __asm_sigaction test = { .sa_handler = handle_it,
#if defined(__x86_64__)
		.sa_restorer = &__restore_rt,
#elif defined(__i386__)
		.sa_restorer = &__restore,
#else
#error "Unrecognised architecture."
#endif
					.sa_flags = SA_RESTORER | SA_NODEFER };
#if defined(__x86_64__)
	int ret = raw_rt_sigaction(SIGUSR1, &test, NULL);
#elif defined(__i386__)
	int ret = raw_sigaction(SIGUSR1, &test, NULL);
#else
#error "Unrecognised architecture."
#endif
	if (ret != 0)
	{
		static const char msg[] = "sigaction() failed!\n";
		raw_write(2, msg, sizeof msg);
		raw_exit(ret);
	}


	int mypid = raw_getpid();
	raw_kill(mypid, SIGUSR1);

	raw_exit(0);
}
