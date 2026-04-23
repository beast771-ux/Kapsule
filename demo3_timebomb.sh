#!/bin/sh
echo -e "\e[1;33m=== RUNNING SCENARIO 3: TIME-BOMB EVASION ===\e[0m"
make clean && make
sudo ./kapsule << 'EOF'
echo "payload dropped" > /tmp/bad.sh
sleep 5
exit
EOF
