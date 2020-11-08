#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

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
} sudo ;

int main() {
	printf("version, flags, uid, sid, starttime_sec, starttime_nsec\n");
	while (sizeof(sudo) == read(0, &sudo, sizeof(sudo))) {
		printf("%d, %d, %d, %d, %d, %d\n",
				sudo.version,
				sudo.flags,
				sudo.auth_uid,
				sudo.sid,
				sudo.start_time.tv_sec,
				sudo.start_time.tv_nsec);
		/* printf("version = %d, ", sudo.version); */
		/* printf("flags %d, ", sudo.flags); */
		/* printf("auth_uid %d, ", sudo.auth_uid); */
		/* printf("sid %d, ", sudo.sid); */
		/* printf("pid start_time %d sec %d nsec\n", */
		/* 		sudo.start_time.tv_sec, */
		/* 		sudo.start_time.tv_nsec); */
	}
	return 0;
}
