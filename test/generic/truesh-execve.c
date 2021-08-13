#include <unistd.h>

int main(void)
{
	return execl("./truesh", "./truesh", NULL);
}
