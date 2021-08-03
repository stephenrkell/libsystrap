#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <err.h>
#include <assert.h>

int main(void)
{
	struct timeval t;
	int ret = gettimeofday(&t, NULL);
	if (ret != 0) err(ret, "getting time of day");
	long secs = t.tv_sec;
	printf("Seconds since epoch (1): %ld\n", secs);
	sleep(2);
	ret = gettimeofday(&t, NULL);
	if (ret != 0) err(ret, "getting time of day");
	long prev_secs = secs;
	secs = t.tv_sec;
	printf("Seconds since epoch (2): %ld\n", secs);
	assert(secs > prev_secs);
	return 0;
}
