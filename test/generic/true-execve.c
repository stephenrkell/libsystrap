#include <unistd.h>

int main(void)
{
	return execl("/bin/true", "/bin/true", NULL);
}
