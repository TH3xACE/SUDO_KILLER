#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

/* Time stamp entry types */
#define TS_GLOBAL               0x01    /* not restricted by tty or ppid */
#define TS_TTY                  0x02    /* restricted by tty */
#define TS_PPID                 0x03    /* restricted by ppid */
#define TS_LOCKEXCL             0x04    /* special lock record */

/* Time stamp flags */
#define TS_DISABLED             0x01    /* entry disabled */
#define TS_ANYUID               0x02    /* ignore uid, only valid in key */

struct header_s {
    unsigned short version;	/* version number */
    unsigned short size;	/* entry size */
    unsigned short type;	/* TS_GLOBAL, TS_TTY, TS_PPID */
    unsigned short flags;	/* TS_DISABLED, TS_ANYUID */
} header;

struct timestamp_entry_v1 {
    unsigned short version;	/* version number */
    unsigned short size;	/* entry size */
    unsigned short type;	/* TS_GLOBAL, TS_TTY, TS_PPID */
    unsigned short flags;	/* TS_DISABLED, TS_ANYUID */
    uid_t auth_uid;		/* uid to authenticate as */
    pid_t sid;			/* session ID associated with tty/ppid */
    struct timespec ts;		/* time stamp (CLOCK_MONOTONIC) */
    union {
	dev_t ttydev;		/* tty device number */
	pid_t ppid;		/* parent pid */
    } u;
};

struct timestamp_entry {
    unsigned short version;	/* version number */
    unsigned short size;	/* entry size */
    unsigned short type;	/* TS_GLOBAL, TS_TTY, TS_PPID */
    unsigned short flags;	/* TS_DISABLED, TS_ANYUID */
    uid_t auth_uid;		/* uid to authenticate as */
    pid_t sid;			/* session ID associated with tty/ppid */
    struct timespec start_time;	/* session/ppid start time */
    struct timespec ts;		/* time stamp (CLOCK_MONOTONIC) */
    union {
	dev_t ttydev;		/* tty device number */
	pid_t ppid;		/* parent pid */
    } u;
};

#define error(msg, ...) { fprintf(stderr, #__VA_ARGS__); exit(1); }

#define PRINT_SUDO(sudo) \
if (read(fd, &entry, sizeof(entry)) != sizeof(entry)) error("read error\n"); \
		printf("===================");\
		printf("version = %d\n", sudo.version);\
		printf("size %d\n", sudo.size);\
		switch (sudo.type) {\
			case TS_GLOBAL: printf("type TS_GLOBAL\n"); break;\
			case TS_TTY: printf("type TS_TTY\n"); break;\
			case TS_PPID: printf("type TS_PPID\n"); break;\
			default: printf("type %d\n", sudo.type); break;\
		}\
		printf("flags %d\n", sudo.flags);\
		printf("auth_uid %d\n", sudo.auth_uid);\
		printf("sid %d\n", sudo.sid);\
		printf("ts %d sec %d nsec\n",\
				sudo.ts.tv_sec,\
				sudo.ts.tv_nsec);\
		printf("ttydev %d\n", sudo.u.ttydev);\
		printf("ppid %d\n", sudo.u.ppid);\


int main() {
	int fd = 0;
	while (read(fd, &header, sizeof(header)) == sizeof(header)) {
		if (lseek(fd, -sizeof(header), SEEK_CUR) == -1) error("lseek error\n");
		if (header.version == 1) {
			struct timestamp_entry_v1 entry;
			PRINT_SUDO(entry);
		}
		else {
			struct timestamp_entry entry;
			PRINT_SUDO(entry);
		}
	}
	/* while (sizeof(sudo) == read(0, &sudo, sizeof(sudo))) { */
        /*  */
	/* 	printf("pid start_time %d sec %d nsec\n",\ */
	/* 			sudo.start_time.tv_sec,\ */
	/* 			sudo.start_time.tv_nsec);\ */
        /*  */
	/* 	#<{(| printf("==================="); |)}># */
	/* 	#<{(| printf("version = %d\n", sudo.version); |)}># */
	/* 	#<{(| printf("size %d\n", sudo.size); |)}># */
	/* 	#<{(| switch (sudo.type) { |)}># */
	/* 	#<{(| 	case TS_GLOBAL: printf("type TS_GLOBAL\n"); break; |)}># */
	/* 	#<{(| 	case TS_TTY: printf("type TS_TTY\n"); break; |)}># */
	/* 	#<{(| 	case TS_PPID: printf("type TS_PPID\n"); break; |)}># */
	/* 	#<{(| 	default: printf("type %d\n", sudo.type); break; |)}># */
	/* 	#<{(| } |)}># */
	/* 	#<{(| printf("flags %d\n", sudo.flags); |)}># */
	/* 	#<{(| printf("auth_uid %d\n", sudo.auth_uid); |)}># */
	/* 	#<{(| printf("sid %d\n", sudo.sid); |)}># */
	/* 	#<{(| printf("pid start_time %d sec %d nsec\n", |)}># */
	/* 	#<{(| 		sudo.start_time.tv_sec, |)}># */
	/* 	#<{(| 		sudo.start_time.tv_nsec); |)}># */
	/* 	#<{(| printf("ts %d sec %d nsec\n", |)}># */
	/* 	#<{(| 		sudo.ts.tv_sec, |)}># */
	/* 	#<{(| 		sudo.ts.tv_nsec); |)}># */
	/* 	#<{(| printf("ttydev %d\n", sudo.u.ttydev); |)}># */
	/* 	#<{(| printf("ppid %d\n", sudo.u.ppid); |)}># */
	/* } */
	return 0;
}
