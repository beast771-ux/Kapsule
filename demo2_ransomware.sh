#!/bin/bash
echo -e "\e[1;31m=== RUNNING SCENARIO 2: RANSOMWARE ATTACK ===\e[0m"
make clean && make
sudo ./kapsule << 'EOF'
cat /etc/passwd
echo "hacked" > /etc/hostname
rm /etc/shadow
wget http://1.1.1.1
exit
EOF
