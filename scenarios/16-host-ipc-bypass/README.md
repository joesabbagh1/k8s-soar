# Scenario 16: Host IPC Namespace Bypass
This scenario simulates a container breakout attack where a compromised pod leverages shared host Inter-Process Communication (IPC) namespaces to bypass container isolation.

## Detection (k8s-soar v2)

Falco rule `K8sSoar Host IPC Access`. Details and known false positives are in
[`docs/detection-catalog.md`](../../docs/detection-catalog.md). After running the scenario,
`make verify-attack ATTACK=host-ipc-bypass` checks that a case was opened for it.
