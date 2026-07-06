# Stage 2 — Credential Access (T1552.001)

## Action
From the Stage 1 foothold shell in the DVWA pod, read the mounted
Kubernetes service account token directly off the container
filesystem:

    cat /var/run/secrets/kubernetes.io/serviceaccount/token

This is the standard first move once inside any Kubernetes pod: the
default service account token is auto-mounted at a well-known path
unless `automountServiceAccountToken: false` is explicitly set, so
any process running as the container user can read it without
further exploitation.

## Detection
Tetragon's process-execution instrumentation captured the exact
command and its outcome at the kernel level:

    process security-lab/dvwa-5d44f5c75d-8rh8k /bin/cat /var/run/secrets/kubernetes.io/serviceaccount/token
    exit    security-lab/dvwa-5d44f5c75d-8rh8k /bin/cat /var/run/secrets/kubernetes.io/serviceaccount/token 0

Exit code 0 confirms the read succeeded — the token was fully
exfiltrated to the attacker's shell at this point. No process or
network anomaly was needed to catch this; a simple exec-tracing
policy on sensitive-path file access is sufficient.

## Implication
This step alone does not compromise anything — Kubernetes RBAC
determines what the token is actually good for. What it enables is
made concrete later, in Stage 5: this exact token was replayed
against the Kubernetes API server directly (bypassing kubectl
entirely) to attempt privilege escalation, and was ultimately denied
by RBAC (see ../stage5-privesc/README.md). Stage 2 and Stage 5
together form a complete "credential theft → attempted abuse" pair,
with detection at the theft step and prevention at the abuse step.
