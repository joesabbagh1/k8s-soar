# Scenario 06 — Missing Security Context / :latest Tag

**MITRE:** Best practice / misconfiguration

## Attack

Deploy a workload to `security-lab` using an unpinned `:latest` image tag and without a non-root security context — a common misconfiguration that increases supply-chain and privilege-escalation risk.

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Kyverno | Audit hits on `k8s-soar-disallow-latest-tag` and `k8s-soar-require-non-root` |
