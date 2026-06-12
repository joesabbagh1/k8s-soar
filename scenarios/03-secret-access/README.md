# Scenario 03 — Service Account Token Access

**MITRE:** T1552 — Unsecured Credentials

## Attack

Read the mounted service account token from the victim pod.

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Falco | `K8sSoar Sensitive Credential Access` |
| Kyverno | Audit on `restrict-sa-automount` for workloads with automount enabled |
