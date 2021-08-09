#include <unistd.h>

int main(void)
{
	return execl("./truemk", "./truemk", NULL);
}
