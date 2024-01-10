#!/bin/bash

cat $1 | while read LINE; do
curl -s https://gtfobins.github.io/gtfobins/"$LINE"/#sudo | html2text | grep "\* Sudo \*" -A 30 > "$LINE".txt
done 
