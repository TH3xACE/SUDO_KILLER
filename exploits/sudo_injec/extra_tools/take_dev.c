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
	signal(SIGUSR1, sig_handler);
	if (ac <= 1) error("Usage: %s [tty]\n", av[0]);
	printf("execve() pid = %d\n", getpid());
	SLEEP;
	printf("fork()\n");
	pid_t pid = fork();
	if (pid < 0) error("Fork error\n");
	if (pid == 0) {
		printf("child pid = %d\n", getpid()); SLEEP;
		close(0);
		printf("close(0)\n"); SLEEP;
		setsid();
		printf("setsid()\n"); SLEEP;
		setpgid(0, 0);
		printf("setpgid()\n"); SLEEP;
		int fd = open(av[1], O_RDONLY);
		printf("open()\n"); SLEEP;
		printf("fd == %d\n", fd);
		printf("tty 0 => %s\n", ttyname(0));
		execlp("/bin/sudo", "/bin/sudo", "ls", 0);
		/* execlp("/bin/sudo", "/bin/sudo", "-S", "ls", 0); */
	} else {
		int status = 0;
		wait(&status);
	}
	return 1;
}
