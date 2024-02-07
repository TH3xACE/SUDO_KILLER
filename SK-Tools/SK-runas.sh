#!/bin/bash
# This script was developed to parse and search for specifc aliases by providing sudoers file 
# V1: Date Created : 08/12/2018
# V2: Date Created : 11/02/2020
# V3: Date Created : 20/07/2023
# Date of last modification : 20/07/2023
# @TH3xACE - BLAIS David 
# https://github.com/TH3xACE/SUDO_KILLER


#!/bin/bash

# Check if a username and command are provided as arguments
if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <username> <command>"
    exit 1
fi

# Get the username and command from command line arguments
username="$1"
shift
command_to_run="$@"

# Use 'su' to switch to the specified user and run the command via a pipe
sudo su - "$username" <<EOF
$command_to_run
EOF

