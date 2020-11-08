#include <sys/stat.h>
#include <fcntl.h>           /* Definition of AT_* constants */
#include <sys/stat.h>

int main() {
	return	fchmod(0, 0777);
}
