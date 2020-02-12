#/bin/sh
echo -e "This is the SUDO_KILLER extractor."
echo -e "WARNING: You should run it only on system you are authorised to do so"
echo -e "https://github.com/TH3xACE/SUDO_KILLER"


cmd=$(sudo -S -l -k)
sudover=`sudo -V 2>/dev/null| grep "Sudo version" 2>/dev/null`

echo "$sudover" > /tmp/sk_offline.txt
echo "$cmd" >> /tmp/sk_offline.txt

