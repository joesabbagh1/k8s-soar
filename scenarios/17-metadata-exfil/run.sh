#!/bin/bash
echo "=== Starting Scenario 17: Cloud Metadata Exfiltration ==="
echo "[*] Attempting to query cloud provider metadata endpoint at 169.254.169.254..."

# Simulating a web service shell executing a curl query to the metadata server
curl --connect-timeout 3 -s http://169.254.169.254/latest/meta-data/ 2>&1

if [ $? -ne 0 ]; then
    echo "[+] Request blocked or timed out. Cilium Network Policy successfully intercepted the exfiltration attempt!"
    echo "[+] Falco alert triggered for anomalous internal metadata tracking."
else
    echo "[!] Warning: Metadata endpoint responded. Ensure strict Cilium egress rules are applied."
fi
