# Scenario 03 — Service Account Token Access

**MITRE:** T1552 — Unsecured Credentials

## Attack

From inside a compromised pod, read the Kubernetes service account token mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token`. Stolen tokens can be used to authenticate to the API server and move laterally within the cluster.

## Run

```bash
./run.sh
```

## Capture

```bash
../../scripts/capture-scenario-evidence.sh 3m 'K8sSoar Sensitive Credential Access'
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Falco | `K8sSoar Sensitive Credential Access` |
| Kyverno | Audit on `restrict-sa-automount` for workloads with automount enabled |
