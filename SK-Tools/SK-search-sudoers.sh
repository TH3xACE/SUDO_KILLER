#!/bin/bash 

# This script was developed for searching sudoers backup files
# Version="version 1.0"
# Date of last modification : 31/07/2023
# @TH3xACE - BLAIS David
# https://github.com/TH3xACE/SUDO_KILLER

##### (Cosmetic) Colour output
RED="\033[01;31m"    # Issues/Errors
GREEN="\033[01;32m"  # Success
YELLOW="\033[01;33m" # Warnings/Information
BLUE="\033[01;34m"   # Heading
BOLD="\033[01;01m"   # Highlight
RESET="\033[00m"     # Normal

echo -e "${YELLOW}[+] Potential sudoers backup files: ${RESET}\n"

grep --color=always -ri "includedir /etc/sudoers.d\|NOPASSWD\:\|(ALL)" /mnt/ /opt/ /etc/ /home/ /app*/ $1 2>/dev/null | sort -u | cut -d ":" -f 1 | grep -v "SK-search-sudoers.sh\|.sh\|.py\|.pl\|.c\|.perl\|.viminfo" | sort -u

