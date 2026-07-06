K8s-SOAR Custom Attack Chain — Lab Scenarios
==============================================

PURPOSE
-------
This directory contains a custom, multi-stage exploitation chain built
by [Tien Anh BUI] to validate the k8s-soar Detect -> Isolate pipeline
end-to-end, since the standard scenarios repository did not exercise
the full stack in enough depth for thesis evidence purposes. Each stage
is a real attacker action (not simulated), executed from a Kali Linux
VM against a deliberately vulnerable pod running inside the k8s-soar
cluster.

Unlike isolated single-technique demos, this chain follows one
continuous narrative: an attacker compromises a public-facing web app,
escalates privileges, attempts lateral movement, and is progressively
shut down by different enforcement layers (Falco, Tetragon, Kyverno,
Cilium) as the attack proceeds.

ATTACK CHAIN — MAPPED TO MITRE ATT&CK FOR CONTAINERS
-----------------------------------------------------
Stage 1 — Initial Access / Execution (T1610 / T1059)
    Kali exploits DVWA's Command Injection module (Low security) to
    pop a reverse shell as www-data inside the dvwa pod.
    File: 01-dvwa.yaml (deployment + service)
    Detection layer: Falco "K8sSoar Shell In Victim Container"

Stage 2 — Credential Access (T1552)
    From the foothold shell, read the pod's mounted service-account
    token to attempt privilege escalation via the Kubernetes API.
    Detection layer: Falco "K8sSoar Sensitive Credential Access"
    -> triggers SOAR quarantine

Stage 3 — Discovery (T1613)
    Using the stolen token, query the K8s API from inside the pod for
    other pods/secrets/namespaces, racing against the SOAR quarantine
    response to see which wins first (a live MTTC data point).

Stage 4 — Command & Control (T1071)
    Open a second reverse shell back to Kali, testing whether the
    already-triggered quarantine has taken effect (network should be
    cut before this connects, if MTTC < time-to-stage-4).
    Detection layer: Falco "K8sSoar Reverse Shell Outbound" +
    Tetragon detect-reverse-shell (Post action, logs only)

Stage 5 — Impact (T1496 / T1611)
    Attempt to write to /etc/shadow (sensitive host write) or spawn a
    process named like a known crypto-miner.
    Detection layer: Tetragon block-sensitive-writes (kernel SIGKILL)
    or Falco "K8sSoar Crypto Miner Process" -> SOAR delete

KNOWN LIMITATION (see falco-detection-gap.md)
----------------------------------------------
During Stage 1 testing, Falco's custom k8s-soar rules did not fire
against the dvwa pod. Root-caused and partially fixed two real bugs
(null-unsafe k8s.ns.name comparison, undefined 'outbound' macro — see
policies/falco/k8s-soar_rules.yaml). A further, unresolved gap remains:
custom rules do not fire on any pod created after Falco's own startup,
even though Falco's own stock rules do. Full writeup, evidence, and
recommended workaround in falco-detection-gap.md.

Given this, Stages 2 onward use Tetragon as the primary detection
layer instead of Falco custom rules, since Tetragon operates
independently of the affected metadata-enrichment pipeline.

FILES IN THIS DIRECTORY
------------------------
01-dvwa.yaml              Stage 1 target deployment (DVWA + NodePort)
falco-detection-gap.md    Root-cause analysis of the Falco detection gap
README.txt                This file
