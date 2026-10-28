# Scenario 18: Kubelet API Unauthorized Reconnaissance
This scenario simulates an attacker performing discovery and reconnaissance against the Kubelet API (Port 10250/10255) from a compromised pod to map out running containers and execute unauthorized commands.

### Detection and Prevention Matrix
* **Runtime Detection:** Falco monitors for anomalous outbound HTTP/HTTPS requests originating from internal application namespaces targeting node infrastructure ports.
* **Kernel Observability:** Tetragon watches for raw socket connections or suspicious curl/wget execution trees interacting with the internal node IP space.

## Detection (k8s-soar v2)

Falco rule `K8sSoar Kubelet Probe`. Details and known false positives are in
[`docs/detection-catalog.md`](../../docs/detection-catalog.md). After running the scenario,
`make verify-attack ATTACK=kubelet-recon` checks that a case was opened for it.
