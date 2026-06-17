# Scenario 04 — Reverse Shell (simulated)

**MITRE:** T1059 — Execution

## Attack

From a compromised container, an adversary uses shell built-ins to open an **outbound TCP connection** (`/dev/tcp/...`), consistent with reverse-shell staging or callback to an external listener. This scenario uses a **non-routable target** (`10.255.255.1`) — no real C2 session is established.

## Scenario flow

| Step | Layer | What happens |
|------|-------|--------------|
| 1. **Attack** | Adversary | From a shell inside a pod in the **`security-lab`** namespace, an outbound TCP connection is attempted to `10.255.255.1:4444` via `/dev/tcp` (reverse-shell staging). |
| 2. **Detection** | Falco | Rule `K8sSoar Reverse Shell Outbound` matches shell process + outbound connection. |
| 3. **Observability** | Tetragon | TracingPolicy `k8s-soar-detect-reverse-shell` records `tcp_connect` events (Post action) on labeled pods. |
| 4. **Triage** | falcosidekick | Critical/Warning alert sent to SOAR webhook. |
| 5. **Response** | SOAR responder | Source pod quarantined via `security.quarantine=true`. |
| 6. **Containment** | Network policy | Further egress blocked for the quarantined pod. |

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Falco | `K8sSoar Reverse Shell Outbound` |
| Tetragon | `tcp_connect` event for scenario pod (see Tetragon logs / `kubectl get tracingpolicy`) |
| falcosidekick | Webhook POST success |
| SOAR responder | Quarantine label applied to scenario pod |

## Capture

```bash
../../scripts/capture-scenario-evidence.sh 3m 'K8sSoar Reverse Shell Outbound'
kubectl get tracingpolicy k8s-soar-detect-reverse-shell
```
