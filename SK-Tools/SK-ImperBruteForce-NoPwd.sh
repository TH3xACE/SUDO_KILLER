#/bin/bash
# https://github.com/TH3xACE/SUDO_KILLER/

##### (Cosmetic) Colour output
RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings/Information
BLUE="\033[01;34m"     # Heading
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal

echo -e "\n"
echo -e "${BLUE} [+] Author: @TH3xACE - BLAIS David"
echo -e "${BLUE} [-] Contribute and collaborate on the KILLER project @ https://github.com/TH3xACE"
echo -e "${RED}  [-] Please consider giving a +1 star on GitHub to show your support! ${RESET}\n"
echo -e "[*] This script aims at identifying impersonation from current user using users from /etc/passwd."
echo -e "[*] Starting from uid 1000, can be used even if a password is need for sudo -l. This is like a impersonation bruteforce"
echo -e "\n"

#1 > path to output /tmp
path=$1

#if [ -z "$path" ] || [ "$path" == "-h" ] ; then
 #echo -e "[+] Output Path: $path"
# echo -e "[+] Usage: ./$0 /<path>"
# exit 1
#else
 #echo -e "[+] Usage: ./$0 /<path>"
 #exit 1
# echo -e "[+] Output Path: $path"
#fi

for I in $(cat /etc/passwd | grep -aw "1[0-9][0-9][0-9]" | cut -d: -f1); 
do 
   rm $path/$I.log 2>/dev/null
   #echo "$I" >> $1/$I.log	
   #echo "--" >> $1/$I.log
   sri=`sudo -l -U $I 2>/dev/null | grep -v "not allowed"`
   if [ "$sri" ]; then
   echo "[+] User $I can be impersonated without password!"
   echo " [-] Exploit: sudo su $I"
   echo " "
  # echo "$I" >> $path/$I.log	
  # echo "--" >> $path/$I.log
  # echo "$sri" >> $path/$I.log
   fi
   #>>$1/$I.log;
   #sudo -l -U 2>/dev/null $I>>$1/$I.log;
done
