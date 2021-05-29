.. raw:: html

   <h1 align="center">

.. image:: ./pictures/SUDO KILLER2.JPG
 	:width: 700px
 	:alt: Project

.. raw:: html

   <br class="title">
   KILLER PROJECT
   <br>

.. image:: https://img.shields.io/github/last-commit/TH3xACE/SUDO_KILLER?style=plastic
   :target: https://github.com/TH3xACE/SUDO_KILLER
   :alt: Last Commit

.. image:: https://img.shields.io/microbadger/image-size/th3xace/sudo_killer_demo?style=plastic
    :target: https://hub.docker.com/r/th3xace/sudo_killer_demo
    :alt: Docker Size

.. image:: https://img.shields.io/docker/cloud/build/koutto/jok3r.svg
    :target: https://hub.docker.com/r/th3xace/sudo_killer_demo
    :alt: Docker Build Status
	
.. raw:: html

   </h1>

#sudo exploitation #Abusing sudo #Exploiting Sudo #Linux Privilege Escalation #OSCP

Linux Privilege Escalation through SUDO abuse.

* **If you like the tool and for my personal motivation so as to develop other tools please a +1 star** 

The tool can be used by pentesters, security auditors, system admins, CTF players, Infosec students and trolls :).


.. contents:: 
    :local:
    :depth: 1

=============
INTRO
=============

**WARNING: SUDO_KILLER is part of the KILLER project. SUDO_KILLER is still under development 
and there might be some issues, please create an issue if you found any. **

**Other tool will be added to the KILLER project in the coming months so stay tuned up. Also ideas, bug reports, contributions are more than welcome !**

** Stay tuned : Follow me on twitter @ https://twitter.com/TH3xACE **

=============
Overview
=============

*SUDO_KILLER* is a tool that can be used for privilege escalation on linux environment by abusing SUDO in several ways. 
The tool helps to identify misconfiguration within sudo rules, vulnerability within the version of sudo being used (CVEs and vulns) and the use of dangerous binary, all of these could be abused to elevate privilege to ROOT.

*SUDO_KILLER* will then provide a list of commands or local exploits which could be exploited to elevate privilege. 
It is worth noting that the tool does not perform any exploitation on your behalf, the exploitation will need to be performed manually and this is intended.


=============
Features
=============

Some of the checks/functionalities that are performed by the tool. 
--------------------------
* **Misconfigurations**
* **Dangerous Binaries**
* **Vulnerable versions of sudo - CVEs**
* **Dangerous Environment Variables**
* **Credential Harvesting**
* **Writable directories where scripts reside**
* **Binaries that might be replaced**
* **Identify missing scripts**

What version 2 of SK includes: 
-------------------------
  * New checks and/or scenarios
	 1. CVE-2019-14287 - runas
	 2. No CVE yet - sudoedit - absolute path
	 3. CVE-2019-18634 - pwfeedback
	 4. User Impersonation
	 5. list of users in sudo group
  * Performance improved
  * Bugs corrected (checks, export, report,...)
  * Continous improvement of the way output presented 
  * New videos will be added soon
  * Annonying password input several time removed
  * New functionality: offline mode - ability to extract the required info from audited system and run SK on host.
  * Testing environment : A docker to play with the tool and different scenarios, you can also train on PE.

New - 2021
-------------------
  * Exploit for CVE-2021-3156 was added
  * Detection for CVE-2021-3156 was added
  * Detection for CVE-2021-23240 was added
  * Exploit for CVE-2019-18634 was added
  * Docker environment to test CVE-2019-18634 was added
  * Video showing exploitation of CVE-2019-18634 was added
  * Video showing exploitation of CVE-2021-3156 was added
  * Arguments bug correction
  * New dangerous bins added (more than 70)

=============
Usage
=============

Example Online mode
--------------------------
 .. code-block:: console
 
 	./sudo_killer.sh -c -e -r report.txt -p /tmp
	
	
Example Offline mode
--------------------------
Run extract.sh on system to be audited/victim machine.
Copy the output from /tmp/sk_offline.txt on the system to be audited/victim machine to your host.

* **Note: Three checks are missing in the offline mode, still in dev... coming soon...**

Run SK with the below parameter:

 .. code-block:: console
 
 	./sudo_killer.sh -c -i /path/sk_offline.txt
	

Optional arguments (Now fully functional : bug corrected)
--------------------------

* **-c : include CVE checks with respect to sudo version**
* **-i : import (offline mode) from extract.sh**
* **-e : include export of sudo rules / sudoers file**
* **-r : report name (save the output)**
* **-p : path where to save export and report**
* **-s : supply user password for sudo checks (If sudo rules is not accessible without current user's password)**
* **-h : help**

**It is worth noting that when using the -c argument, the CVEs identified are only based on the sudo version in used.**
**Very often, a sudo version might be vulnerable but specific condition must be met for exploitation.**

**SK also check if some conditions are met for several CVEs without the -c such as CVE-2014-0106, CVE-2015-5602, CVE-2017-1000367, CVE-2019-14287, CVE-2019-18634, CVE-2021-3156 and CVE-2021-23240**

CVEs check
--------------------------

To update the CVE database : run the following script ./cve_update.sh


Providing password (**Important**)
--------------------------

If you need to input a password to run sudo -l then the script will not work if you don't provide a password with the argument -s.

How to run SK on the targetted/audited machine
--------------------------

**If you are on a machine that has internet connection, just git clone the tool and run it. If you are on a machine that does not have internet, then git clone on your host, compress the tool (tar) then transfert the compressed file via http/smb (apache web server / python simplehttpserver / smb server / nc) then uncompressed the file on the targeted system and enjoy!**



Notes
--------------------------

**NOTE : sudo_killer does not exploit automatically by itself, it was designed like this on purpose but check for misconguration and vulnerabilities and then propose you the following (if you are lucky the route to root is near!) :

* **a list of commands to exploit** 
* **a list of exploits**
* **some description on how and why the attack could be performed**

=============
Why is it possible to run "sudo -l" without a password?
=============
By default, if the NOPASSWD tag is applied to any of the entries for a user on a host, you will be able to run "sudo -l" without a password. This behavior may be overridden via the verifypw and listpw options.

However, these rules only affect the current user, so if user impersonation is possible (using su) sudo -l should be launched from this user as well.

Sometimes the file /etc/sudoers can be read even if sudo -l is not accessible without password.


============
Docker - Vulnerable testing environment
============
**IMPORTANT: The recommended way to test the tool is to use the docker image created on purpose for the testing. The image contained several vulnerabilities and misconfigurations related to
the usage of SUDO.

Everything is tested from the Docker container available on Docker Hub !**

.. image:: https://raw.githubusercontent.com/koutto/jok3r/master/pictures/docker-logo.png

A Docker image is available on Docker Hub and automatically re-built at each update: 
https://hub.docker.com/r/th3xace/sudo_killer_demo . It is initially based on official debian:jessie Docker image (debian:jessie).

.. image::https://img.shields.io/microbadger/image-size/th3xace/sudo_killer_demo ?style=plastic
    :target: https://hub.docker.com/r/th3xace/sudo_killer_demo
    :alt: Docker Size


1. **Pull SUDO_KILLER_DEMO Docker Image from the docker hub :**

    .. code-block:: console

        service docker start 
	docker pull th3xace/sudo_killer_demo
	docker run --rm -it th3xace/sudo_killer_demo		

2. **Build locally from Dockerfile (This version maybe a bit more up-to-date):**

    .. code-block:: console

        service docker start 
	git clone https://github.com/TH3xACE/SUDO_KILLER.git 
	cd SUDO_KILLER 
	docker build -t th3xace/sudo_killer_demo . 
	docker run --rm -it th3xace/sudo_killer_demo

3. **Pull SUDO_KILLER_DEMO2 Docker Image from the docker hub : (if you want to test CVE-2019-18634 (pwfeedback))**

    .. code-block:: console

        service docker start 
	docker pull th3xace/sudo_killer_demo2
	docker run --user 1000 --rm -it th3xace/sudo_killer_demo2
	
	Then follow guidance from the tool, It should be noted that the version 1.8.25 was used for the demo and that for other versions slight changes should be made.Refer to the readme in the exploit folder for more info. There is also a video for the exploitation. Credits to the POC exploit's developper refer to 	    notes.


**Note: It is important to note that the docker is just an environment that can be used to play with the tool since it contains several vulns to exploit. The tool is meant to be used on its own.**

============
Demos
============

Several videos are provided below with different scenarios of exploitation.

The playlist url: https://www.youtube.com/watch?v=Q8iO9mYrfv8&list=PLQPKPAuCA40FMpMKWZLxQydLe7rPL5bml

+----------------------------------------------------------+----------------------------------------------------------+
|* **Video 1 : Docker - Setup vuln environment**	   |* **Video 8: Scenario 7 -  Environment Variable** 	      |
|.. raw:: html						   |.. raw:: html					      |
|							   |							      |
|  <a href="https://youtu.be/Q8iO9mYrfv8">   		   |  <a href="https://youtu.be/sGd8KW_eqhw">   	      |
|  <img src="./pictures/p1.JPG" width="350" height="200">  |  <img src="./pictures/p8.JPG" width="350" height="200">  |
|  </a>							   |  </a>						      |
+----------------------------------------------------------+----------------------------------------------------------+
|* **Video 2 : Scenario 1 - CVE exploitation**		   |* **Video 9: Scenario 8 - CVE-2019-14287 - runas**	      |	
|.. raw:: html						   |.. raw:: html					      |
|							   |							      |
|  <a href="https://youtu.be/CpLJ9kY6eig">   		   |  <a href="https://youtu.be/Dn1zfEcVHJY">   	      |
|  <img src="./pictures/p2.JPG" width="350" height="200">  |  <img src="./pictures/p7.JPG" width="350" height="200">  |
|  </a>							   |  </a>						      |
+----------------------------------------------------------+----------------------------------------------------------+
|* **Video 3 : Scenario 2 - Dangerous Bins**		   |* **Video 10: Scenario 9 - sudoedit - absolute path**     |	
|.. raw:: html						   |.. raw:: html					      |
|							   |							      |
|  <a href="https://youtu.be/cELFVC6cTyU">   		   |  <a href="https://youtu.be/TlWzT97pjr8">   	      |
|  <img src="./pictures/p3.JPG" width="350" height="200">  |  <img src="./pictures/p6.JPG" width="350" height="200">  |
|  </a>							   |  </a>						      |
+----------------------------------------------------------+----------------------------------------------------------+
|* **Video 4 : Scenario 3 - Misconfig (Wildcard)**  	   |* **Video 11: Scenario 10 - User impersonation I [X2]**   |
|.. raw:: html						   |.. raw:: html					      |
|							   |							      |
|  <a href="https://youtu.be/rKA55mis8-4">   		   |  <a href="https://youtu.be/9oV8xQrPcuY">   	      |
|  <img src="./pictures/p4.JPG" width="350" height="200">  |  <img src="./pictures/p5.JPG" width="350" height="200">  |
|  </a>							   |  </a>						      |
+----------------------------------------------------------+----------------------------------------------------------+
|* **Video 5 : scenario 4 - Misconfig (Excessive Rights)** |* **Video 12: Scenario 10 - User impersonation II**       |
|.. raw:: html						   |.. raw:: html					      |
|							   |							      |
|  <a href="https://youtu.be/s1KK6go1nGY">   		   |  <a href="https://youtu.be/CvVIAERN_3s">   	      |
|  <img src="./pictures/p5.JPG" width="350" height="200">  |  <img src="./pictures/p4.JPG" width="350" height="200">  |
|  </a>							   |  </a>						      |
+----------------------------------------------------------+----------------------------------------------------------+
|* **Video 6 : Scenario 5 - Misconfig (Missing scripts)**  |* **Video 13: Scenario 11 - CVE-2019-18634-pwfeedback**   | 	
|.. raw:: html						   |.. raw:: html					      |
|							   |							      |
|  <a href="https://youtu.be/zsxvsSYz4as">   		   |  <a href="https://youtu.be/LhqbExt5oq0">   	      |
|  <img src="./pictures/p6.JPG" width="350" height="200">  |  <img src="./pictures/p4.JPG" width="350" height="200">  |
|  </a>							   |  </a>						      |
+----------------------------------------------------------+----------------------------------------------------------+
|* **Video 7 : Scenario 6 - Credentials Harvesting**	   |* **Video 14: Scenario 11 - CVE-2021-3156**               |	
|.. raw:: html						   |.. raw:: html					      |
|							   |							      |
|  <a href="https://youtu.be/i7ixN0sv2Qw">   		   |  <a href="https://youtu.be/AJSSRrGt-Dw">   	      |
|  <img src="./pictures/p7.JPG" width="350" height="200">  |  <img src="./pictures/p4.JPG" width="350" height="200">  |
|  </a>							   |  </a>						      |
+----------------------------------------------------------+----------------------------------------------------------+
|* **Video 15 : offline mode**	                           |* **Video 16: TBD**                                       |	
|.. raw:: html						   |.. raw:: html					      |
|							   |							      |
|  <a href="https://youtu.be/i7ixN0sv2Qw">   		   |  <a href="https://youtu.be/LhqbExt5oq0">   	      |
|  <img src="./pictures/px.jpg" width="350" height="200">  |  <img src="./pictures/px.jpg" width="350" height="200">  |
|  </a>							   |  </a>						      |
+----------------------------------------------------------+----------------------------------------------------------+


=============
Coming functionality and improvement
=============

* **Detection of CVE-2021-3156 - done** 
* **Adding CVE-2021-3156 scenario to docker - done**
* **Detection of CVE-2021-23240 - done**
* **Adding CVE-2021-23240 scenario to docker + exploit - coming**
* **Credentials harvesting - done**
* **Improve the way information on potential vuln and exploit are presented - done**
* **Adding scenario + detection exploit for CVE-2019-14287 - done**
* **Ability to extract data and do analysis offline - on your machine - partially done**
* **Perform the checks (identify vulnerabilities) even if the sudo's rules not accessible without password provided you have current user's password and provided by using the argument -s and waiting for password prompt**
* **Sudo token abuse - done**
* **Dealing with aliases**
* **Extracting sudo rules remotely via SSH (fully automated)**
* **Blind SUDO - This is a new sub-project (whenever you need a password to run sudo -l but you don't have it)**
* **Audit mode (need to have read access to /etc/sudoers)**

* **If you want me to add any other one... please submit an issue**

=============
Support - Stargazers over time
=============

Thank you all for your support!

|Ask Me Anything !|

.. |Ask Me Anything !| image:: https://starchart.cc/TH3xACE/SUDO_KILLER.svg
   :target: https://starchart.cc/TH3xACE/SUDO_KILLER

=============
Credits
=============
The script was developed by myself with the help of online resources found on github and in the wild. Credits also to the authors of the exploits related to CVEs.
The authors information and links can be found in the exploit and in the notes provided when running the tool. Special kudos to Vincent Puydoyeux, who gave me the idea to develop this tool and Koutto, for helping me with the docker thing and for improving the tool.


=============
Disclaimer
=============
This script is for Educational purpose ONLY. Do not use it without permission of the owner of the system you are running it. The usual disclaimer applies, especially the fact that me (TH3xACE) is not liable for any damages 
caused by direct or indirect use of the information or functionality provided by these programs. The author or any Internet provider bears NO responsibility for content or misuse 
of these programs or any derivatives thereof. By using these programs you accept the fact that any damage (dataloss, system crash, system compromise, etc.) caused by the use of 
the script is not my responsibility.


