#!/bin/bash

#file=$1
file=$(ls | grep bins*.txt)
tempf="conca-temp.txt"
tempu="conca-new.txt"

toupdate="dbinstoupdate.txt"

line_count_old=$(cat "$file" | grep ".md" | wc -l)
#line_count_old=$(wc -l < "$file")

FILENAME="bins_$(date +'%d-%m-%y').txt"


echo "[-] Last Check:" $file
echo "[-] Current CHeck" $FILENAME


  if [ $file != $FILENAME ]; then

        #curl -s "https://api.github.com/repos/GTFOBins/GTFOBins.github.io/contents/_gtfobins" | jq -r '.[].name' > "$FILENAME"
        curl -s "https://api.github.com/repos/GTFOBins/GTFOBins.github.io/contents/_gtfobins" | grep -oP '"name": "\K[^"]+'  | grep ".md" >  "$FILENAME"

        cat "$FILENAME" >> "$tempf"
        cat "$file" >> "$tempf"
        cat "$tempf" | sort -u > "$tempu"
      
        #line_count_new=$(wc -l < "$FILENAME")
        line_count_new=$(cat "$tempu" | grep ".md" | wc -l)

        if [ "$line_count_new" -gt "$line_count_old" ]; then
            new_add=$((line_count_new - line_count_old - 1))
            echo "[+] There are $new_add additions:"

            grep -v -F -f "$FILENAME" "$tempu"  | sed 's/\.md//g' >> "$toupdate"
            grep -v -F -f "$file" "$tempu"  | sed 's/\.md//g' >> "$toupdate"
            cat "$toupdate" | sort -u

            rm "$tempf"
            rm "$tempu"

            mv $file old/

            echo "[+] Downloading new additions in the directory newAdd"

            cat $toupdate | sort -u | while read LINE; do
            #pline=$( LINE | sed 's/.md//g' )
            # 
            #curl -s https://gtfobins.github.io/gtfobins/"$LINE"/#sudo | html2text | grep "\* Sudo \*" -A 30 > newAdd/"$LINE".txt
            #curl -s https://gtfobins.github.io/gtfobins/"$LINE"/#sudo | html2text | awk '/SUID/{found=1; next} !found {print}' > newAdd/"$LINE".txt
            
            curl -s https://gtfobins.github.io/gtfobins/"$LINE"/#sudo | html2text | grep "\* Sudo \*" -A 1000  | awk '/SUID/{found=1; next} !found {print}' > newAdd/"$LINE".txt
            #echo $LINE

            done 

            echo "[+] Moving the new additions in the directory dbins"
            mv newAdd/*.txt ../

            rm "$toupdate"

        else
            echo "[-] The are no additions, please check again later!"
            mv $file old/
        
        fi

else
 echo "[+] Update Already done today!"
fi



