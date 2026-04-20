#!/bin/bash
echo -e "\e[1;36m=== RUNNING SCENARIO 1: CLEAN SANDBOX ===\e[0m"
make clean && make
sudo ./kapsule << 'EOF'
hostname
ps
touch /tmp/hello
exit
EOF
