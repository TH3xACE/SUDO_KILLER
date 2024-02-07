#!/bin/bash
# This script was developed to parse and search for specifc aliases by providing sudoers file 
# V1: Date Created : 08/12/2018
# V2: Date Created : 11/02/2020
# V3: Date Created : 20/07/2023
# Date of last modification : 20/07/2023
# @TH3xACE - BLAIS David 
# https://github.com/TH3xACE/SUDO_KILLER


##### (Cosmetic) Colour output
RED="\033[01;31m"    # Issues/Errors
GREEN="\033[01;32m"  # Success
YELLOW="\033[01;33m" # Warnings/Information
BLUE="\033[01;34m"   # Heading
BOLD="\033[01;01m"   # Highlight
RESET="\033[00m"     # Normal

# List of binaries to check
binaries_to_check="bash cat chmod cp ls mkdir mv rm echo grep ping ps su fdisk ifconfig iptables mount umount reboot shutdown curl python tar unzip wget nano git gcc crond sshd ntpd sysctl node docker nginx ruby python python2 python3 find"

# Function to extract non-full path binaries from a script file
# function find_non_full_path_binaries() {
#     local script_file="$1"
#     while read -r line; do
#         # Use regex to find non-full path binaries in the script
#         found_binaries=$(echo "$line" | grep -oE "(^|\s)(./|[^/[:space:]]+/)[^[:space:]]+")
#         while read -r bin_name; do
#             # Check if the binary is a non-full path (not starting with '/')
#             if [[ "$bin_name" != /* ]]; then
#                 echo "Found non-full path binary: $bin_name at line $line_num in $script_file"
#             fi
#         done <<< "$found_binaries"
#         ((line_num++))
#     done < "$script_file"
# }


function find_non_full_path_binaries() {

local script_file="$1"
    # while read -r line; do
    #      found_binaries=$(echo "$line" | grep -oE "\b($(IFS='|'; echo "${binaries_to_check[*]}"))\b")
    #      echo $line

    # done < "$script_file"

  count=0
  cat $script_file | while read line 
  do
    #echo $line 
     #count=count+1
     ((count++))
    for value in $binaries_to_check; do
        #echo "Current value: $value"
        chkbins=`echo $line | grep -iw $value | grep -v "\#" | grep -v "print" | cut -d " " -f 1 | grep -v "/" 2>/dev/null`
        if [ $chkbins ]; then
        echo -e "Found non-full path binary: ${YELLOW}$value${RESET} at line $count in $script_file"          
        fi
    done

  done

}


# Check if at least one argument (script file) is provided
if [ $# -lt 1 ]; then
    echo "Usage: $0 <script_file1> [<script_file2> ...]"
    exit 1
fi

# Loop through each script file provided as input
for script_file in "$@"; do
    # Check if the file exists and is readable
    if [ -f "$script_file" ] && [ -r "$script_file" ]; then
        line_num=1
        echo -e "Checking $script_file for non-full path binaries..."
        echo -e "--------------------------------------------------\n"
        find_non_full_path_binaries "$script_file"
        echo -e "---------- \n"
    else
        echo "Error: Cannot read $script_file. Skipping..."
    fi
done

