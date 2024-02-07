#!/bin/bash
# This script was developed to parse and search for specifc aliases by providing sudoers file 
# V1: Date Created : 08/12/2018
# V2: Date Created : 11/02/2020
# V3: Date Created : 20/07/2023
# Date of last modification : 20/07/2023
# @TH3xACE - BLAIS David 
# https://github.com/TH3xACE/SUDO_KILLER


sudoers_path=$1
alias_keyword=$2
#alias_content=$3
#alias_type=$4

##### (Cosmetic) Colour output
RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings/Information
BLUE="\033[01;34m"     # Heading
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal


#alias_type="User_Alias"
#cat $1 | grep "$alias_type" | sed 's/$alias_type//g'| sed 's/^#//g' | cut -d= -f1,2 | awk '{$1=$1;print}'

#echo "Search by alias name:"
#cat $1 | grep "$alias_type" | sed "s/$alias_type//g"| sed 's/^#//g' | cut -d= -f1,2 | awk '{$1=$1;print}' | cut -d "=" -f1 | grep -i $alias_keyword
#cat $sudoers_path | grep -i "$alias_type" | awk -v kw="pilotage" -F= '{if ($1 ~ /"pilotage"/) { print $0; }}'

# Using awk with the variable as search keyword (case-insensitive)
#result=$(echo "$input_text" | awk -F= -v search="$search_keyword" 'BEGIN{IGNORECASE=1} {if (tolower($1) ~ search) { print $0; }}')
#cat $sudoers_path | grep -i "$alias_type" | awk -F= -v search="$alias_keyword" 'BEGIN{IGNORECASE=1} {if (tolower($1) ~ search) { print $0; }}'

# Print the result
#echo "$result"

#echo -e "\n"

#echo "Search by alias content:"
#cat $1 | grep "$alias_type" | sed "s/$alias_type//g"| sed 's/^#//g' | cut -d= -f1,2 | awk '{$1=$1;print}' | cut -d "=" -f2 | grep -i $alias_content

#cat $sudoers_path | grep -i "$alias_type" | awk -F= '{if ($2 ~ /$alias_keyword/) { print $0; }}'

#cat $sudoers_path | grep -i "$alias_type" | awk -F= -v search="$alias_keyword" 'BEGIN{IGNORECASE=1} {if (tolower($2) ~ search) { print $0; }}'

#if [ -z "$alias_content" ]; then
#cat $1 | grep "$alias_type" | sed "s/$alias_type//g"| sed 's/^#//g' | cut -d= -f1,2 | awk '{$1=$1;print}' | cut -d "=" -f2 
#else
#cat $1 | grep "$alias_type" | sed "s/$alias_type//g"| sed 's/^#//g' | cut -d= -f1,2 | awk '{$1=$1;print}' | cut -d "=" -f2 | grep -i $alias_content
#fi

print_aliases()
{
local alias_typ=$1
#local alias_kw=$2
echo -e "\n"
echo -e "${BLUE}[-] Search in alias type: $alias_typ :${RESET}"
echo -e "==============================================\n"

echo -e "${YELLOW}[*] Search in alias name:${RESET}"
echo -e "----------------------------------------\n"
cat $sudoers_path | grep -i "$alias_typ" | awk -F= -v search="$alias_keyword" 'BEGIN{IGNORECASE=1} {if (tolower($1) ~ search) { print $0; }}' | sed "s/$alias_typ//g"| sed 's/^#//g' | cut -d= -f1,2 | awk '{$1=$1;print}' | grep -i "$alias_keyword" --colour


echo -e "\n"

echo -e "${YELLOW}[*] Search in alias content:${RESET}"
echo -e "-----------------------------------------\n"
cat $sudoers_path | grep -i "$alias_typ" | awk -F= -v search="$alias_keyword" 'BEGIN{IGNORECASE=1} {if (tolower($2) ~ search) { print $0; }}' | sed "s/$alias_typ//g"| sed 's/^#//g' | cut -d= -f1,2 | awk '{$1=$1;print}' | grep -i "$alias_keyword" --colour


}


# Check if any arguments are provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 -p <sudoers_path> -k "<keyword>" [-u] [-r] [-m] [-c] | [-a]"
    exit 1
fi

# Loop through the provided arguments and check for valid options
while getopts "p:k:urmca" opt; do
    case "$opt" in
         p) sudoers_path="$OPTARG"
	    echo "$sudoer_path"
	    ;;
         k) alias_keyword="$OPTARG"
	    echo -e "----------------------------------------------------"
	    echo -e "[+] Keyword: ${GREEN}$alias_keyword${RESET}\n"
	    echo -e "----------------------------------------------------"
	    ;;
	 u) #echo "User_Alias aliases:"
            print_aliases "User_Alias"
            echo  # Newline after each alias type
            ;;
        r)
            #echo "Runas_Alias aliases:"
            print_aliases "Runas_Alias"
            echo  # Newline after each alias type
            ;;
        m)
            #echo "Host_Alias aliases:"
            print_aliases "Host_Alias"
            echo  # Newline after each alias type
            ;;
        c)
            #echo "Cmnd_Alias aliases:"
            print_aliases "Cmnd_Alias"
            echo  # Newline after each alias type
            ;;
        a)
            #echo "All aliases:"
            #echo "User_Alias aliases:"
            print_aliases "User_Alias"
            echo  # Newline after each alias type
            #echo "Runas_Alias aliases:"
            print_aliases "Runas_Alias"
            echo  # Newline after each alias type
            #echo "Host_Alias aliases:"
            print_aliases "Host_Alias"
            echo  # Newline after each alias type
            #echo "Cmnd_Alias aliases:"
            print_aliases "Cmnd_Alias"
            echo  # Newline after each alias type
            ;;
        \?)
            echo "Invalid option: -$OPTARG"
            exit 1
            ;;
        :)
            echo "Option -$OPTARG requires an argument."
            exit 1
            ;;
    esac
done
