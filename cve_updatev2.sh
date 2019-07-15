#! /bin/sh
# to update the sudo's CVEs database


rm cve.sudo2.txt

wget -O cve_list.html -t 2 https://www.cvedetails.com/vulnerability-list.php?vendor_id=118

cat cve_list.html | grep 'CVE-' | grep "href=" | cut -d"=" -f 2 | sed 's/  title/ /g' | sed 's/"//g' | sed 's/\/c/https:\/\/www.cvedetails.com\/c/g' > cve_url.txt

cat cve_url.txt | while read line

do

var_cve=$( echo -n "$line" |cut -d "/" -f5 ) 

# echo -n " + "
# echo $var_cve

echo -n $var_cve >> cve_list.txt
echo -n " + " >> cve_list.txt

curl $line   | grep 'title="External url"' | grep 'href' | cut -d'"' -f 2 |  tr '\n' ' ' >> cve_list.txt

# curl $line | grep 'title="Todd Miller Sudo ' | cut -d "=" -f 3 | cut -d '"' -f 2 >> cve_list.txt

echo -n " + " >> cve_list.txt

curl $line | grep 'title="Todd Miller Sudo ' | cut -d "=" -f 3 | cut -d '"' -f 2 | tr '\n' ' ' >> cve_list.txt


# curl $line | grep 'title="Todd Miller Sudo ' | cut -d "=" -f 3 | cut -d '"' -f 2 | tr '\n' ' ' | sed 's/ CVE/\n CVE/g' | sed 's/Todd Miller Sudo / /g' | sed 's/ P/p/g' >> cve_list.txt

done


cat cve_list.txt | sed 's/ CVE/\n CVE/g' | sed 's/Todd Miller Sudo / /g' | sed 's/ P/p/g' >> cve.sudo2.txt
echo "\n" >> cve.sudo2.txt
cat cve.sudo.manual.txt >> cve.sudo2.txt

#sed -in '{s/CVE\-1999\-0958\ + \[URL\]/CVE\-1999\-0958 https:\/\/marc.info\/?l=bugtraq\&m\=88465708614896\&w\=2/g}' cve.sudo2.txt 
 
#sed -in '{s/CVE\-2002\-0043\ + \[URL\]/CVE\-2002\-0043 https:\/\/marc.info\/?l\=bugtraq\&m\=101120193627756\&w\=2/g}' cve.sudo2.txt 

#sed -in '{s/CVE\-2002\-0184\ + \[URL\]/CVE\-2002\-0184 https:\/\/www.exploit\-db.com\/exploits\/21420\//g}' cve.sudo2.txt 

#sed -in '{s/CVE\-2004\-1051\ + \[URL\]/CVE\-2004\-1051 https:\/\/marc.info\/?l\=bugtraq\&m\=110028877431192&w\=2/g}' cve.sudo2.txt 

#sed -in '{s/CVE\-2005\-1831\ + \[URL\]/CVE\-2005\-1831 https:\/\/marc.info\/?l\=bugtraq\&m\=111755694008928&w\=2/g}' cve.sudo2.txt 

#sed -in '{s/CVE\-2006\-0151\ + \[URL\]/CVE\-2006\-0151\ https:\/\/www.securityfocus.com\/bid\/16184\/discuss \- https:\/\/downloads.securityfocus.com\/vulnerabilities\/exploits\/sudo_local_perl_root.txt \- https:\/\/downloads.securityfocus.com\/vulnerabilities\/exploits\/sudo_local_python_exploit.txt/g}' cve.sudo2.txt 

#sed -in '{s/CVE\-2007\-3149\ + \[URL\]/CVE\-2007\-3149 https:\/\/www.securityfocus.com\/bid\/24368\/exploit/g}' cve.sudo2.txt 

#sed -in '{s/CVE\-2012-0809\ + \[URL\]/CVE\-2012-0809 https:\/\/www.exploit\-db.com\/exploits\/18436\/ \- https:\/\/www.exploit\-db.com\/exploits\/25134\//g}' cve.sudo2.txt 

#sed -in '{s/CVE\-2012-2337\ + \[URL\]/CVE\-2012-2337 https:\/\/www.securityfocus.com\/bid\/53569\/exploit/g}' cve.sudo2.txt 

#sed -in '{s/CVE\-2017\-1000368\ + \[URL\]/CVE\-2017\-1000368 https:\/\/www.securityfocus.com\/bid\/98838\/info/g}' cve.sudo2.txt 

#sed -in '{s/CVE\-2009\-0034\ + \[URL\]/CVE\-2009\-0034 https:\/\/www.cvedetails.com\/cve\/CVE\-2009\-0034\//g}' cve.sudo2.txt 

#sed -in '{s/CVE\-2010-1163\ + \[URL\]/CVE\-2010-1163 https:\/\/www.securityfocus.com\/bid\/39468\/exploit/g}' cve.sudo2.txt 

#sed -in '{s/CVE\-2016\-7032\ + \[URL\]/CVE\-2016\-7032 https:\/\/www.securityfocus.com\/bid\/95776\/exploit \- https:\/\/bugzilla.redhat.com\/show_bug.cgi?id\=1372830/g}' cve.sudo2.txt 
  
#sed -in '{s/CVE\-2017\-1000367\ + \[URL\]/CVE\-2017\-1000367 https:\/\/bugzilla.redhat.com\/show_bug.cgi?id\=1372830/g}' cve.sudo2.txt 

#sed -in '{s/CVE\-2014\-0106\ + \[URL\]/CVE\-2014\-0106 https:\/\/www.securityfocus.com\/bid\/65997\/exploit/g}' cve.sudo2.txt 

#sed -in '{s/CVE\-2014\-0106\ + \[URL\]/CVE\-2014\-0106 https:\/\/www.securityfocus.com\/bid\/65997\/exploit/g}' cve.sudo2.txt


rm cve_list.txt 
rm cve_list.html
rm cve_url.txt





