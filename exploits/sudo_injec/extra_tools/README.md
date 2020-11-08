parse_process_stat: parse /proc/[pid]/stat

Usage: ./parse_process_stat [pid]

Everything is parsed but only starttime is printed.

Example:
```sh
./parse_process_stat 4242
/proc/4242/stat.starttime => 193691
```

read_sudo_token: parse /var/run/sudo/ts/[username]

Usage: ./read_sudo_token < /var/run/sudo/ts/[username]

parse all sudo token

Example:

```sh
# ./tsdump -f /var/run/sudo/ts/test 
position: 0
version: 2
size: 56
type: TS_LOCKEXCL
flags: 
auth uid: 0
session ID: 0

position: 56
version: 2
size: 56
type: TS_TTY
flags: TS_DISABLED
auth uid: 1001
session ID: 1594
start time: Wed Mar 27 23:20:11 2019
terminal: /dev/pts/1
```

spawn_process_pid: spawn a shell that has a given pid

Usage: ./spawn_process_pid [pid]

Example:

```sh
bash$ ./spawn_process_pid 12345
sh$ echo $$
12345
```
# tsdump to read sudo token or (sudo timestamp)

./configure CFLAGS="-static"


https://github.com/ThomasHabets/injcode

https://blog.nelhage.com/2011/02/changing-ctty/
https://blog.habets.se/2009/03/Moving-a-process-to-another-terminal.html
