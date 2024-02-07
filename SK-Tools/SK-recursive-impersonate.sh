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
echo -e "[*] This script aims at identifying recursive impersonation with a default depth of 3."
echo -e "\n"

# Intial - Get a list of potential users that can be impersonated from initial user sudo's rules
#user=`sudo -l | grep "NOPASSWD:" | grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | awk '{print $NF}' | sed 's/\*//g' | sort -u`
user=$(sudo -l | grep "NOPASSWD:" | grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | grep -iv "\-c" | awk '{print $NF}' | sed 's/\*/\/*/g' | sort -u)

# Clean
echo "" > impuser.txt

cp SK-runas.sh /tmp/skras.sh

if [ "$user" ]; then
    
    echo -e "--------------------------------"
    echo -e "   ${BOLD}${YELLOW}LEVEL 1${RESET} : From $USER  ${BOLD}${BLUE}[1 jump]${RESET}"
    echo -e "--------------------------------"

    # check all the users gathered from sudo against /etc/passwd since wildcard could have been used.
    echo "$user" | while IFS= read -r line; 
    do
        #to decomment - just for lab test since using number in username to track easier
        #cat /etc/passwd | cut -d: -f 1 | grep -iw "$line" >> impuser.txt 
        #imusr=`cat /etc/passwd | cut -d: -f 1 | grep -iw "$line\$"` 
        imusr=$(cat /etc/passwd | cut -d: -f 1 | grep -ia "$line") 
        #echo $line
        if [ "$imusr" ]; then
        echo $imusr >> impuser.txt 
        echo -e "${BOLD}${RED}[+] "$USER" -> "$imusr" ${RESET} " 
        sudo -l 2>/dev/null| grep "NOPASSWD:" | grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | grep -iv "\-c" | grep -i $line 
        echo -e "\n"
        fi    
    done

       echo "" > impuser1.txt

    if [ -f "$PWD/impuser.txt" ]; then

           echo -e "--------------------------------"
           echo -e "   ${BOLD}${YELLOW}LEVEL 2${RESET} : ${BOLD}${BLUE}[2 jumps]${RESET}"
           echo -e "--------------------------------"

        # Check level 1 - Impersonation
        
            cat "$PWD"/impuser.txt | sort -u | while read line1
            do  
                
              # user=`sudo -l | grep "NOPASSWD:" | grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | awk '{print $NF}' | sed 's/\*/\/*/g' | sort -u`
              # user1=`sudo /bin/su $line1 -c "export PATH="/usr/local/bin:$PATH"; sudo -l | grep "NOPASSWD:" | grep -iw "/\*bin/su \*" | grep -v "su root" | grep -v "/\*bin/su \-\$\|/\*bin/su \*\$\|/\*bin/su \- \*\$" | awk '{print $NF}'"` 
                #sdr1=$(sudo /bin/su "$line1" 2>/dev/null -c "export PATH="/usr/local/bin:$PATH"; sudo -l 2>/dev/null") 
                sdr1=$(bash SK-runas.sh $line1 "sudo -l")
                #echo $sdr1
                if [ "$sdr1" ]; then
                
                #$echo "$sdr1"
                #user1=`echo "$sdr1" | grep "NOPASSWD:"| grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | sed 's/\*/\/*/g' | grep -v root | sort -u | awk '{print $NF}' | sed '/^[[:space:]]*$/d'`
                 user1=$(echo "$sdr1" | grep "NOPASSWD:"| grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | sed 's/*/\/*/g' | grep -iv "\-c" | awk '{print $NF}')                       
                    #echo "$user1"
                    echo "$user1" | while IFS= read -r line2; 
                        do
                          if [ "$line2" ]; then
                            #imusr=`cat /etc/passwd | cut -d: -f 1 | grep -iw "$line\$"` 
                            imusr1=$(cat /etc/passwd | cut -d: -f 1 | grep -ia "$line2" 2>/dev/null) 
                            #echo $line
                            if [ "$imusr1" ]; then


                            # Split the variable into an array using space as the delimiter
                            #IFS=' ' read -ra elements <<< "$imusr1"

                            # Iterate over each element in the array
                              for element in $imusr1; do
                              #for element in "${elements[@]}"; do
                                  #echo "$element"
                                   #echo "$line1,$imusr1" >> impuser1.txt 
                                   #echo -e "${BOLD}${RED}[+] "$USER" -> "$line1" -> "$imusr1" ${RESET}" 
                                   echo "$line1,$element" >> impuser1.txt 
                                   echo -e "${BOLD}${RED}[+] "$USER" -> "$line1" -> "$element" ${RESET}" 
                                   sr1=$(echo "$sdr1" | grep "NOPASSWD:" | grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | grep -iv "\-c" | grep -i $line2) 
                                   echo "$sr1"
                                   echo -e "\n"
                              done

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
        
            #cat $PWD/impuser1.txt
            cat $PWD/impuser1.txt | sort -u | while read line3
            do  
                
                prlvl=$(echo $line3 | cut -d"," -f1)
                crlvl=$(echo $line3 | cut -d"," -f2)

                if [ "$crlvl" ]; then
                # user=`sudo -l | grep "NOPASSWD:" | grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | awk '{print $NF}' | sed 's/\*/\/*/g' | sort -u`
                # user1=`sudo /bin/su $line1 -c "export PATH="/usr/local/bin:$PATH"; sudo -l | grep "NOPASSWD:" | grep -iw "/\*bin/su \*" | grep -v "su root" | grep -v "/\*bin/su \-\$\|/\*bin/su \*\$\|/\*bin/su \- \*\$" | awk '{print $NF}'"` 
                sdr1=$(bash /tmp/skras.sh $prlvl "bash /tmp/skras.sh $crlvl "sudo -l 2>/dev/null"")                #echo $crlvl
                #sdr1=$(sudo /bin/su "$crlvl" 2>/dev/null -c "export PATH="/usr/local/bin:$PATH"; sudo -l 2>/dev/null") 
                if [ "$sdr1" ]; then
                
                #$echo "$sdr1"
                #user1=`echo "$sdr1" | grep "NOPASSWD:"| grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | sed 's/\*/\/*/g' | grep -v root | sort -u | awk '{print $NF}' | sed '/^[[:space:]]*$/d'`
                 user1=$(echo "$sdr1" | grep "NOPASSWD:"| grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | sed 's/*/\/*/g' |  awk '{print $NF}')                       
                    #echo "$user1"
                    echo "$user1" | while IFS= read -r line4; 
                        do
                          if [ "$line4" ]; then
                            #imusr=`cat /etc/passwd | cut -d: -f 1 | grep -iw "$line\$"` 
                            imusr2=$(cat /etc/passwd | cut -d: -f 1 | grep -ia "$line4" 2>/dev/null) 
                            #echo $line
                            if [ "$imusr2" ]; then
                            echo "$imusr2" >> impuser2.txt 
                           echo -e "${BOLD}${RED}[+] "$USER" -> "$prlvl" -> "$crlvl" -> "$imusr2" ${RESET} " 
                            sr1=$(echo "$sdr1" | grep "NOPASSWD:" | grep -iw "/*bin/su *" | grep -v "su root" | grep -v "/*bin/su -$\|/*bin/su \*$\|/*bin/su \- \*$" | grep -i $line4) 
                            echo "$sr1"
                            echo -e "\n"
                            fi   
                         fi 
                        done

                fi

              fi

            done

        fi



fi # initial check

rm impuser*.txt
rm /tmp/skras.sh






