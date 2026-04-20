#!/bin/bash
echo -e "\e[1;35m=== RUNNING SCENARIO 4: RESOURCE HOG (OOM) ===\e[0m"
make clean && make
sudo ./kapsule << 'EOF'
awk 'BEGIN{ while(1) a[i++]="Consume all the RAM in the system..."; }'
exit
EOF
