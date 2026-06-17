# Scenario 08 — Sensitive Host Path Write (simulated)

**MITRE:** T1611 — Escape to Host

## Attack

From inside a container, attempt to append data to `/etc/shadow`, a sensitive credential store. This simulates an attacker probing for host-level impact or persistence via sensitive filesystem paths.

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Falco | File access alerts |
| Tetragon | `k8s-soar-block-sensitive-writes` action (when policy loaded) |
