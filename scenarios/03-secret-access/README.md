# Scenario 03 — Service Account Token Access

**MITRE:** T1552 — Unsecured Credentials

## Attack

Read the mounted service account token from dedicated pod `scenario-03-token` (`scenario=03`).

## Run

```bash
./run.sh
# or
./scripts/capture-scenario-evidence.sh 3m 'K8sSoar Sensitive Credential Access'
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Falco | `K8sSoar Sensitive Credential Access` |
| Kyverno | Audit on `restrict-sa-automount` for workloads with automount enabled |
