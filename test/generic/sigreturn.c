#include <signal.h>
#include <sys/types.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>

static void handle_it(int signum)
{
	static const char msg[] = "Got SIGUSR1! Resuming...\n";
	write(2, msg, sizeof msg);
}

int main(void)
{
	struct sigaction myaction = (struct sigaction) {
		.sa_handler = handle_it
	};
	int ret = sigaction(SIGUSR1, &myaction, NULL);
	assert(ret == 0);

	pid_t mypid = getpid();
	kill(mypid, SIGUSR1);

	return 0;
}
