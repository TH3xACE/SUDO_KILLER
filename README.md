![Static Badge](https://img.shields.io/badge/Version-3.0.1-blue)
![GitHub last commit (branch)](https://img.shields.io/github/last-commit/TH3xACE/SUDO_KILLER/V3)
![Static Badge](https://img.shields.io/badge/Maintain-Yes-purple)
![Static Badge](https://img.shields.io/badge/Author-TH3xACE-red)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/TH3xACE/SUDO_KILLER/)

:star: Star us on GitHub — to show your support!

<p align="left">
    <img width="100%" src="https://github.com/TH3xACE/res/blob/main/SK/sk-logo.gif" alt="logo"/>
</p>


[![Twitter](https://img.shields.io/twitter/url/https/twitter.com/cloudposse.svg?style=social&label=%40TH3xACE)](https://twitter.com/th3xace)
[![LinkedIn](https://img.shields.io/badge/-LinkedIn-black.svg?style=flat-square&logo=linkedin&colorB=blue)](https://www.linkedin.com/in/adblais)

 :bulb: Best Viewed in Dark Mode :)


:wrench::wrench::wrench::wrench: WORK IN PROGRESS - Not officially Launch


- [ Intro ](#intro)
- [ Usage ](#usage)
- [ Docker ](#docker)
- [ Checks ](#check)
- [ Scenarios ](#scenarios)
- [ Video (demo) ](#videos)
- [ CVEs ](#CVEs)
- [ SK-Tools ](#sk-tools)
- [ Stargazers ](#stars)
- [ Contribution ](#contribute)
- [ Support ](#support)
- [ Credits ](#credits)
- [ Disclaimers ](#disclaimer)
- [ License ](#license)

<a name="intro"></a>
## Introduction

`SUDO_KILLER` is a tool geared towards cyber security practitioners (pentesters, security auditors, system admins, CTF players and Infosec students ), facilitating privilege escalation within Linux environments. It focuses on vulnerabilities tied to SUDO usage, including misconfigurations in sudo rules, version-based weaknesses (CVEs and vulnerabilities), and risky binary deployments (GTFOBINS). These weak points can be exploited to gain ROOT-level privileges or impersonate users.

`SUDO_KILLER` provides a catalog of potential commands and local exploits for manual privilege elevation. Importantly, it refrains from automated exploitation, requiring users to carry out the exploitation process themselves as per its intended usage.

<a name="check"></a>
## Checks

Below is a list of checks that are perform by `SUDO_KILLER`
- Misconfigurations
- Dangerous Binaries (GTFOBINS)
- Vulnerable versions of sudo - CVEs
- Sudo vulnerability and misconfiguration related to 3rd party apps
- Dangerous Environment Variables
- Credential Harvesting
- Writable directories where scripts reside
- Binaries that might be replaced
- Identify missing scripts

> [!WARNING]
> The check list above is NOT exhaustive.

<a name="usage"></a>
## Usage 

To get started with SUDO_KILLER, you can either git clone or download the zip. If you want to practice and/or test it, there is a vulnerable testing enviroment (docker) see the video on it which provides an overview on how to setup the docker and run SUDO_KILLER. Several scenarios can be setup in the docker environment and can be used for testing different misconfigurations or flaws. Alternatively, you can run it on the system to be audited to check for misconfigurations and/or flaws related to sudo.

```shell
./SUDO_KILLERv<version>.sh -c -a -e -r report.txt -p /tmp
```

Optional arguments:
</br>-c : includes CVE checks</br>
-a : includes CVEs related to third party apps/devices </br>
-i : import (offline mode) from extract.sh </br>
-e : include export of sudo rules / sudoers file </br>
-r : report name (save the output) </br>
-p : path where to save export and report </br>
-s : supply user password for sudo checks (If sudo rules is not accessible without current user's password) </br>
-h : help

> [!NOTE]
> It is worth noting that when using the -c argument, two types of check are provided one for which the CVE identified is solely based on the current sudo version being used and another where the requirements are also checked.
> Very often, a sudo version might be vulnerable but some pre-requisites might be needed for a successful exploitation.

> [!NOTE]
> Providing password: If you need to input a password to run sudo -l then the script will not work if you don't provide a password with the argument -s.

<a name="docker"></a>
## Docker (Vulnerable testing environment)

<p align="left">
    <img width="25%" src="https://github.com/TH3xACE/res/blob/main/SK/docker.gif" alt="-dockerlogo"/>
</p>

A range of Docker containers is made available to offer a deliberately vulnerable environment for testing and hands-on experimentation with `SUDO_KILLER` as well as with the vulnerabilities. 

```shell
service docker start 
docker pull th3xace/sudo_killer_demo
docker run --rm -it th3xace/sudo_killer_demo3
```
```shell
(This docker is only to test the CVE-2019-18634 (pwfeedback))
service docker start 
docker pull th3xace/sudo_killer_demo2
docker run --user 1000 --rm -it th3xace/sudo_killer_demo2
```

## Why is it possible to run "sudo -l" without a password?

By default, if the NOPASSWD tag is applied to any of the entries for a user on a host, you will be able to run "sudo -l" without a password. This behavior may be overridden via the verifypw and listpw options.

However, these rules only affect the current user, so if user impersonation is possible (using su) sudo -l should be launched from this user as well.

Sometimes the file /etc/sudoers can be read even if sudo -l is not accessible without password.


<a name="scenarios"></a>
## Scenarios

To switch scenario (To prevent conflicts between the different scenarios) on the docker (demo3):

```shell
switchScenario <scenario_number>

Available scenarios: 0 to 10
All Scenarios 0 : Conflict might occur!
Scenario 1: [2,3] CVE - Rules
Scenario 2: [4] Excessive permissions
Scenario 2: [5] Excessive permissions (Authentication required)
Scenario 3: [6] User Impersonation
Scenario 4: [7] Common Misconfiguration (Change owner)
Scenario 4: [8,11] Common Misconfiguration (Wildcard)
Scenario 5: [13] Missing scripts from sudo rules
Scenario 6: [17] Dangerous Environment Variables
Scenario 7: [18] Dangerous binaries (gtfobins)
Scenario 8: [19] Recursive Impersonation test
Scenario 9: [20] Environment Path Hijacking
Scenario 10: [21] App Specific sudo vuln/misconfig
Scenario 11: [5] Excessive permissions (Authentication required)
Scenario 12: [16] Backdooring sudo (Credentials Capture)
```

<a name="videos"></a>
## Videos - Demo 

The playlist can be found here: [https://www.youtube.com/watch?v=Q8iO9mYrfv8&list=PLQPKPAuCA40FMpMKWZLxQydLe7rPL5bml](https://www.youtube.com/watch?v=VjXiLhmOmHs&list=PLQPKPAuCA40ERFDNZ-Ub58SgGHGKAcr26)

> [!IMPORTANT]
> Quick videos on how to properly do the testing on the provided docker.

<details open>
<summary>
     (click to expand) Usage : How to setup and use the provided testing environment (docker)
</summary> <br />
    
<p align="center">
   <a href="#">  
      <img width="39%" src="https://github.com/TH3xACE/res/blob/main/SK3/Slide1.JPG" alt="apis"/>
   </a>
&nbsp;
   <a href="https://youtu.be/VjXiLhmOmHs">  
      <img width="39%" src="https://github.com/TH3xACE/res/blob/main/SK3/Slide2.JPG" alt="apis"/>
   </a>
</p>

<p></p>

</p>    
</details>

> [!WARNING]
> The video list below is not exhaustive, to have access to all the videos, please check the playlist link.

<details open>
<summary>
     Several videos are provided below with different scenarios of exploitation.
</summary> <br />
    
<p align="center">
   <a href="https://youtu.be/rg6FxPuP8sQ">  
     <img width="39%" src="https://github.com/TH3xACE/res/blob/main/SK3/Slide3.JPG" alt="apis"/>
   </a>
&nbsp;
   <a href="https://youtu.be/BBtoBrZdAKk">  
     <img width="39%" src="https://github.com/TH3xACE/res/blob/main/SK3/Slide9.JPG" alt="apis"/>
   </a>
</p>

<p align="center">
   <a href="https://youtu.be/XiLsS9v3hy8">  
     <img width="39%" src="https://github.com/TH3xACE/res/blob/main/SK3/Slide10.JPG" alt="apis"/>
   </a>
&nbsp;
    <a href="https://youtu.be/eBfIotMsDiI">  
     <img width="39%" src="https://github.com/TH3xACE/res/blob/main/SK3/Slide11.JPG" alt="apis"/>
   </a>
</p> 

<p align="center">
   <a href="https://youtu.be/a68dAmgeJnA">  
     <img width="39%" src="https://github.com/TH3xACE/res/blob/main/SK3/Slide12.JPG" alt="apis"/>
   </a>
&nbsp;
    <a href="https://youtu.be/CILd01m2GBs">  
     <img width="39%" src="https://github.com/TH3xACE/res/blob/main/SK3/Slide13.JPG" alt="apis"/>
   </a>
</p> 

<p align="center">
   <a href="https://youtu.be/4xectsHBfCQ">  
     <img width="39%" src="https://github.com/TH3xACE/res/blob/main/SK3/Slide14.JPG" alt="apis"/>
   </a>
&nbsp;
    <a href="https://youtu.be/11q5pzGJxvk">  
     <img width="39%" src="https://github.com/TH3xACE/res/blob/main/SK3/Slide15.JPG" alt="apis"/>
   </a>
</p> 

<p align="center">
   <a href="https://youtu.be/BbPBxXy4rKY">  
     <img width="39%" src="https://github.com/TH3xACE/res/blob/main/SK3/Slide16.JPG" alt="apis"/>
   </a>
&nbsp;
    <a href="https://youtu.be/sfkxoR2a99o">  
     <img width="39%" src="https://github.com/TH3xACE/res/blob/main/SK3/Slide17.JPG" alt="apis"/>
   </a>
</p> 

<p align="center">
   <a href="https://youtu.be/SV2KPd4CA8A">  
     <img width="39%" src="https://github.com/TH3xACE/res/blob/main/SK3/Slide18.JPG" alt="apis"/>
   </a>
&nbsp;
    <a href="https://youtu.be/6Lt-wKZmH9c">  
     <img width="39%" src="https://github.com/TH3xACE/res/blob/main/SK3/Slide19.JPG" alt="apis"/>
   </a>
</p> 

    
</details>

<a name="CVEs"></a>
## CVEs

<details open>
<summary>
  (click to expand) CVEs related to SUDO that SUDO_KILLER detects (including pre-requisites): 
</summary> <br />

<p align="center">
   <a href="https://youtu.be/THS_bn4MOQY">  
     <img width="39%" src="https://github.com/TH3xACE/res/blob/main/SK3/Slide4.JPG" alt="apis"/>
   </a>
&nbsp;
    <a href="https://youtu.be/6VkZaj3FDiE">  
     <img width="39%" src="https://github.com/TH3xACE/res/blob/main/SK3/Slide5.JPG" alt="apis"/>
   </a>
</p> 

<p align="center">
   <a href="https://youtu.be/LhqbExt5oq0">  
     <img width="39%" src="https://github.com/TH3xACE/res/blob/main/SK3/Slide7.JPG" alt="apis"/>
   </a>
&nbsp;
    <a href="https://youtu.be/AJSSRrGt-Dw">  
     <img width="39%" src="https://github.com/TH3xACE/res/blob/main/SK3/Slide8.JPG" alt="apis"/>
   </a>
</p> 

<p align="center">
   <a href="https://youtu.be/elwGRlN7aCI">  
     <img width="39%" src="https://github.com/TH3xACE/res/blob/main/SK3/Slide6.JPG" alt="apis"/>
   </a>
&nbsp;
</p> 


</details>

<details open>
<summary>
  (click to expand) Recent CVEs of 3rd party apps/devices related to sudo that SUDO_KILLER detects (including pre-requisites): 
</summary> <br />

<p align="center">
   <a href="https://youtu.be/CP0S_7aZHxA">  
     <img width="39%" src="https://github.com/TH3xACE/res/blob/main/SK3/Slide27.JPG" alt="apis"/>
   </a>
&nbsp;
    
</p> 



</details>


<a name="sk-tools"></a>
## SK-Tools
Version 3 of `SUDO_KILLER` now includes a list of tools that can be used to achieve several tasks. The scripts are located at `SUDO_KILLERv3/SK-Tools`

- $\color{#f0a015}\large{\textsf{SK-ImperBruteForce-NoPwd.sh:}}$ Perform an impersonation bruteforce using users from /etc/passwd, starting from user with uid 1000.
- $\color{#f0a015}\large{\textsf{SK-credHarvest2.sh:}}$ Perform a credential capture by creating a fake sudo via alias then re-direct to real sudo.
- $\color{#f0a015}\large{\textsf{SK-app-check.sh:}}$ Perform check of sudo vulnerabilities related to a specifc third-party app or device or programming lang [still in progress].
- $\color{#f0a015}\large{\textsf{SK-ttyInject.sh:}}$ Abusing TTY pushback so that if the user root su - on a controlled user we make him run an arbitrary command.
- $\color{#f0a015}\large{\textsf{SK-recursive-impersonate.sh:}}$ Perform identification of recursive impersonation with a default depth of 3.
- $\color{#f0a015}\large{\textsf{SK-alias-report.sh:}}$ Perform search on alias with different criteria.
- $\color{#f0a015}\large{\textsf{SK-csuid-with-sudo.sh:}}$ Perform identification of custom suid binary then check whether sudo command is run without full path.
- $\color{#f0a015}\large{\textsf{SK-su-BruteForce.sh:}}$ Perform password bruteforce or password spray for a specific user via sudo.
- $\color{#f0a015}\large{\textsf{SK-search-sudoers.sh:}}$ Perform an identification of possible sudoers backup files on the current host.

<details open>
<summary>
     (click to expand) Usage : SK-Tools
</summary> <br />
    
<p align="center">
   <a href="https://youtu.be/Oc1yuploiME">  
     <img width="39%" src="https://github.com/TH3xACE/res/blob/main/SK3/Slide20.JPG" alt="apis"/>
   </a>
&nbsp;
    <a href="https://youtu.be/aoofrCyb6KA">  
     <img width="39%" src="https://github.com/TH3xACE/res/blob/main/SK3/Slide21.JPG" alt="apis"/>
   </a>
</p> 

<p align="center">
   <a href="https://youtu.be/gUDuZVwVWyU">  
     <img width="39%" src="https://github.com/TH3xACE/res/blob/main/SK3/Slide22.JPG" alt="apis"/>
   </a>
&nbsp;
    <a href="https://youtu.be/7VqNCgYvEa0">  
     <img width="39%" src="https://github.com/TH3xACE/res/blob/main/SK3/Slide23.JPG" alt="apis"/>
   </a>
</p> 

<p align="center">
   <a href="https://youtu.be/AG1o6s4dEF0">  
     <img width="39%" src="https://github.com/TH3xACE/res/blob/main/SK3/Slide24.JPG" alt="apis"/>
   </a>
&nbsp;
    <a href="https://youtu.be/woF68JmJ33c">  
     <img width="39%" src="https://github.com/TH3xACE/res/blob/main/SK3/Slide25.JPG" alt="apis"/>
   </a>
</p> 

<p align="center">
   <a href="https://youtu.be/R3_u-G5AyUw">  
     <img width="39%" src="https://github.com/TH3xACE/res/blob/main/SK3/Slide26.JPG" alt="apis"/>
   </a>
&nbsp;
    <a href="https://youtu.be/Vpr00SxIVgo">  
     <img width="39%" src="https://github.com/TH3xACE/res/blob/main/SK3/Slide28.JPG" alt="apis"/>
   </a>
</p> 

</details>

</br>

## Capturing Credentials (via sudo redirect)
The script SK-credHarvest2.sh from SK-Tools allow to perform a credential capture by creating a fake sudo via alias then re-direct to real sudo. Actually works only for bash (not working/implemented for ZSH or else for now)configured linux.

The displayed message when asking for credential when using sudo differs from the version being used. It is possible to choose between two options (differ based on OS version).
Example of the displayed message (new and old)

> [!TIP]
> (new) [sudo] password for user: <br />
> (old) Password: 

For All Users (auser):
When you have root privilege or excessive rights on users' home and you want an easy way to gather credentials:
```shell
./SK-credHarvest2.sh auser <new|old> ; source /home/*/.bashrc
```
For the currrent user (cuser):
```shell
./SK-credHarvest2.sh cuser <new|old> ; source /home/<currentuser>/.bashrc
```
> [!CAUTION]
> TO STOP the credential harvesting: run the same script again with same argument

output: the log /tmp/sk-crds.log will contains the credentials

<a name="contribute"></a>
## Contributing

`SUDO_KILLER` is an open-source project and highly appreciate any contributions. Whether you are helping us fix bugs, proposing new features, improving our documentation or spreading the word - we would love to have you as a contributor. Please reach me on twitter or Linkedin if you have any suggestions, feedback or want to contribute, you can also create a Pull Request. I am looking for contribution on the sudo CVEs related to 3rd party (I have a list of about 175) and any help would be appreciated.

- Bug Report: If you see an error message or run into an issue while using `SUDO_KILLER`, please create a [bug report](https://github.com/TH3xACE/SUDO_KILLER/issues/new?assignees=&labels=type%3A+bug&template=bug.yaml&title=%F0%9F%90%9B+Bug+Report%3A+).

- Feature Request: If you have an idea or you're missing a capability that would make development easier and more robust, please submit a [feature request](https://github.com/TH3xACE/SUDO_KILLER/issues/new?assignees=&labels=type%3A+feature+request&template=feature.yml).

<a name="stars"></a>
## Stargazers over time 

Thank you all for your support!

[![Stargazers over time](https://starchart.cc/TH3xACE/SUDO_KILLER.svg?variant=adaptive)](https://starchart.cc/TH3xACE/SUDO_KILLER)



<a name="support"></a>
## Support

<a href="https://www.patreon.com/TH3xACE">
	<img src="https://c5.patreon.com/external/logo/become_a_patron_button@2x.png" width="160">
</a>

<a name="credits"></a>
## Credits

I crafted the script independently, leveraging online resources from GitHub and other sources in the wild. Acknowledgments are also due to the creators of exploits associated with CVEs. You can trace their details and references in the exploit itself, as well as in the accompanying notes when the tool is executed. Notable recognition extends to Vincent Puydoyeux, whose inspiration spurred the development of this tool, and Koutto, for invaluable assistance in handling Docker intricacies and enhancing the tool's functionality. Additionally, a heartfelt thank you goes out to Emilio Pinna (norbemi) and Andrea Cardaci (cyrus_and) for their invaluable contributions to GTFO Bins, which significantly influenced this project's development.

<a name="disclaimer"></a>
## Disclaimer

This script is for Educational purpose ONLY. Do not use it without permission of the owner of the system you are running it. The usual disclaimer applies, especially the fact that me (TH3xACE) is not liable for any damages caused by direct or indirect use of the information or functionality provided by this project. The author (TH3xACE) or any Internet provider bears NO responsibility for content or misuse of these programs or any derivatives thereof. By using these programs you accept the fact that any damage (dataloss, system crash, system compromise, etc.) caused by the use of the script is not the author responsibility.

<a name="license"></a>
## License

`SUDO_KILLER` is licensed under the MIT license, proper credits is expected whenever used. Please consider to donate for any commercial use.
