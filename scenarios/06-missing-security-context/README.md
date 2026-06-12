# Scenario 06 — Missing Security Context / :latest Tag

**MITRE:** Best practice / misconfiguration

## Attack

Deploy pod using `:latest` tag without runAsNonRoot.

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Kyverno | Audit hits on `k8s-soar-disallow-latest-tag` and `k8s-soar-require-non-root` |
