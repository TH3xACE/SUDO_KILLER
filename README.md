# SUDO_KILLER
Script written in bash to assist in the exploitaton of sudo (Misconfiguration + Vulnerabilities)

# Default usage
Example: ./sudo_killer.sh -c -r report.txt -e /tmp/

# Arguments 
-k : Keywords
-e : export location
-c : include CVE checks with respect to sudo version
-s : supply user password for sudo checks (not recommended ++except for CTF)
-r : report name
-h : help

# CVEs check
To update the CVE database : run the following script ./cve_update.sh

# NOTE : sudo_killer does not exploit but check for misconguration and vulnerabilities and then propose you the following :
+ a list of commands
+ a list of exploits
+ some description on how and why the attack could be performed

# IMPORTANT !!!
If you need to input a password to run sudo -l then the script will not work if you provide password with the argument -s.


# Why it is possible to run "sudo -l" without a password?

By default, if the NOPASSWD tag is applied to any of the entries for a user on a host, he or she will be able to run "sudo -l" without a password. This behavior may be overridden via the verifypw and listpw options.

However, these rules only affect the current user, so if user impersonation is possible (using su) sudo -l should be launched from this user as well. 

Sometimes the file /etc/sudoers can be read even if sudo -l is not accessible without password.


# Testing the script :)

$ docker build -t privesc/cve-2015-5602 .

$ docker run --rm -it privesc/cve-2015-5602

$ vim /etc/sudoers
** paste
user ALL=(root) NOPASSWD: /directory/*/user*/setup.sh

user ALL=(root) NOPASSWD: /bin/chown -hR * /home/user/directory/*

user ALL=(root) NOPASSWD: /bin/chown -hR * *.txt

user ALL=(root) NOPASSWD: /bin/chown -HR * *.txt

user ALL=NOPASSWD: sudoedit /home/*/*/esc.txt

user ALL=NOPASSWD: /home/user/support/start.sh, /home/user/support/stop.sh, /home/user/support/restart.sh, /usr/sbin/lsof

root@c0631a24f588:/home/user# mkdir support

root@c0631a24f588:/home/user# cd support/

root@c0631a24f588:/home/user/support# touch restart.sh

root@c0631a24f588:/home/user/support# touch start.sh

root@c0631a24f588:/home/user/support# chmod u+rwx restart.sh 

root@c0631a24f588:/home/user/support# chmod g+xr restart.sh 

root@c0631a24f588:/home/user/support# chmod o+x restart.sh 

root@c0631a24f588:/home/user/support# chown user:user start.sh 

root@c0631a24f588:/home/user/support# chmod u+rwx start.sh 

root@c0631a24f588:/home/user/support# chmod g+xr start.sh 

root@c0631a24f588:/home/user/support# chmod o+x start.sh 

root@c0631a24f588:/home/user/support# cd ../

root@c0631a24f588:/home/user# chown user:user support/



# Credits
The script was written by myself but with the help of a lot of online ressources found on github and in the wild, I thanks those people who inspire me. The credits and the links are shown when their exploits/decriptions are used when running the script



 
