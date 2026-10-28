# Scenario 17: Cloud Metadata Exfiltration
This scenario simulates an attacker attempting to query the cloud provider metadata endpoint (169.254.169.254) from within a compromised pod to steal IAM security credentials.

## Detection (k8s-soar v2)

Falco rule `K8sSoar Cloud Metadata Access`. Details and known false positives are in
[`docs/detection-catalog.md`](../../docs/detection-catalog.md). After running the scenario,
`make verify-attack ATTACK=metadata-exfil` checks that a case was opened for it.
