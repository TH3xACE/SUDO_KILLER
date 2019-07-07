#sudo exploitation #Abusing sudo #Exploiting Sudo

If you like the project and for my personal motivation so as to develop other tools please a +1 star *

# SUDO_KILLER
SUDO_KILLER is a tool which help to abuse SUDO in different ways and with the main objective of performing a privilege escalation on linux environment. 

The tool helps to identify misconfiguration within sudo rules, vulnerability within the version of sudo being used (CVEs and vulns) and the used of dangerous binary, all of these could be abuse to elevate privilege to ROOT. 

SUDO_KILLER will then provide with a list of commands or local exploits which could be exploited to elevate privilege.

SUDO_KILLER does not perform any exploitation on your behalf, the exploitation will need to be performed manually and this is intended.



# Default usage
Example: ./sudo_killer.sh -c -r report.txt -e /tmp/

# Arguments 
-k : Keywords \
-e : export location (export /etc/sudoers) \
-c : include CVE checks with respect to sudo version \
-s : supply user password for sudo checks (not recommended ++except for CTF) \
-r : report name (save the output) \
-h : help 

# CVEs check
To update the CVE database : run the following script ./cve_update.sh

# IMPORTANT !!!
If you need to input a password to run sudo -l then the script will not work if you don't provide a password with the argument -s.

**NOTE : sudo_killer does not exploit automatically by itself, it was designed like this on purpose but check for misconguration and vulnerabilities and then propose you the following (if you are lucky the route to root is near!) :
+ a list of commands to exploit
+ a list of exploits
+ some description on how and why the attack could be performed

# Why is it possible to run "sudo -l" without a password?

By default, if the NOPASSWD tag is applied to any of the entries for a user on a host, he or she will be able to run "sudo -l" without a password. This behavior may be overridden via the verifypw and listpw options.

However, these rules only affect the current user, so if user impersonation is possible (using su) sudo -l should be launched from this user as well. 

Sometimes the file /etc/sudoers can be read even if sudo -l is not accessible without password.


# Testing the tool :)
$ git clone https://github.com/t0kx/privesc-CVE-2015-5602.git \
$ cd privesc-CVE-2015-5602 \
$ docker build -t privesc/cve-2015-5602 . \
$ docker run --rm -it privesc/cve-2015-5602 \
$ ./exploit.sh \
copy the password and use the password \
$ su root \
$ apt-get install git \
$ git clone https://github.com/TH3xACE/SUDO_KILLER.git

$ vim /etc/sudoers
** paste
<p>user ALL=(root) NOPASSWD: /directory/*/user*/setup.sh </p>
<p>user ALL=(root) NOPASSWD: /bin/chown -hR * /home/user/directory/* </p>
<p>user ALL=(root) NOPASSWD: /bin/chown -hR * *.txt  </p>
<p>user ALL=(root) NOPASSWD: /bin/chown -HR * *.txt   </p>
<p>user ALL=NOPASSWD: sudoedit /home/*/*/esc.txt   </p>
<p>user ALL=NOPASSWD: /home/user/support/start.sh, /home/user/support/stop.sh, /home/user/support/restart.sh, /usr/sbin/lsof   </p>
<p>user ALL=(root) NOPASSWD: /direc/*/user  </p>
<p>user ALL=(root) NOPASSWD: /bin/cp *  </p>


root@sudo_exploit:/home/user# mkdir support \
root@sudo_exploit:/home/user# cd support/ \
root@sudo_exploit:/home/user/support# touch restart.sh \
root@sudo_exploit:/home/user/support# touch start.sh \
root@sudo_exploit:/home/user/support# chmod u+rwx restart.sh \
root@sudo_exploit:/home/user/support# chmod g+xr restart.sh \
root@sudo_exploit:/home/user/support# chmod o+x restart.sh \
root@sudo_exploit:/home/user/support# chown user:user start.sh   
root@sudo_exploit:/home/user/support# chmod u+rwx start.sh \
root@sudo_exploit:/home/user/support# chmod g+xr start.sh \
root@sudo_exploit:/home/user/support# chmod o+x start.sh \
root@sudo_exploit:/home/user/support# cd ../ \
root@sudo_exploit:/home/user# chown user:user support/ 

exit \
cd SUDO_KILLER \
./sudo_killerv1.3.1.sh

# Credits
The script was written by myself but with the help of a lot of online ressources found on github and in the wild, I thanks those people who inspire me. The credits and the links are shown when their exploits/decriptions are used when running the script.

Special kudos to Vincent Puydoyeux :) who gave me the idea to develop this tool.

# Disclaimer

This script is for Educational purpose ONLY. Do not use it without permission. The usual disclaimer applies, especially the fact that me (TH3xACE) is not liable for any damages caused by direct or indirect use of the information or functionality provided by these programs. The author or any Internet provider bears NO responsibility for content or misuse of these programs or any derivatives thereof. By using these programs you accept the fact that any damage (dataloss, system crash, system compromise, etc.) caused by the use of the script is not my responsibility.



 
