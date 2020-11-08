#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

void sig_handler(int signo)
{
  if (signo == SIGUSR1)
    printf("received SIGUSR1\n");
}

#define error(msg, ...) { fprintf(stderr, #__VA_ARGS__); exit(1); }
/* #define SLEEP sleep(99999999999); */
#define SLEEP sleep(0);

int main(int ac, char **av) {
	if (ac <= 1) error("Usage: %s [tty]\n", av[0]);
	setsid();
	setpgid(0, 0);
	close(0);
	close(1);
	close(2);
	int fd0 = open(av[1], O_RDWR);
	int fd1 = open(av[1], O_RDWR);
	int fd2 = open(av[1], O_RDWR);
	int out = open("/tmp/out", O_RDWR | O_CREAT);
	/* printf("out => %d\n", out); */
	dprintf(out, "fd = %d %d %d\n", fd0, fd1, fd2);
	dprintf(out, "ttyname %s\n", ttyname(0));
	system("/bin/sudo ls");
	/* execlp("/bin/sudo", "/bin/sudo", "ls", 0); */
	/* execlp("/bin/sudo", "/bin/sudo", "ls", 0); */
	return 1;
}
