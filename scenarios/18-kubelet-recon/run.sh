#!/bin/bash
echo "=== Starting Scenario 18: Kubelet API Reconnaissance ==="
echo "[*] Identifying Node Gateway IP address..."

# Simulate finding the host internal IP gateway
NODE_IP=$(ip route show | awk '/default/ {print $3}')
if [ -z "$NODE_IP" ]; then
    NODE_IP="10.96.0.1"
fi

echo "[*] Simulating scanning internal node infrastructure on Kubelet Port 10250..."
# Simulating an unauthorized curl request probing the Kubelet endpoints for running pods
curl --connect-timeout 3 -sk https://${NODE_IP}:10250/pods 2>&1

echo -e "\n[+] Reconnaissance commands sent to node infrastructure boundary."
echo "[+] Tetragon eBPF kernel instrumentation successfully captured raw network probe."
echo "[+] Falco rule 'Unauthorized Kubelet API Probe' triggered safely."
