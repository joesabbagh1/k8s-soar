# Stage 5 — Privilege Escalation (T1611 / T1548)

## Action
From the Stage 1 foothold (www-data shell in the DVWA pod), enumerated
the pod's runtime security posture and mounted service account
identity, then attempted to use the stolen SA token to escalate
privileges via the Kubernetes API directly.

Enumeration (see `capabilities.log`):
- Container capabilities: standard Docker default set only
  (CHOWN, DAC_OVERRIDE, FOWNER, FSETID, KILL, SETGID, SETUID,
  SETPCAP, NET_BIND_SERVICE, NET_RAW, SYS_CHROOT, MKNOD,
  AUDIT_WRITE, SETFCAP) — no SYS_ADMIN, SYS_PTRACE, or SYS_MODULE.
  No `privileged: true`, no NoNewPrivs restriction, no seccomp
  profile, but also no elevated capabilities to abuse for a direct
  container/kernel escape.
- A default service account token, CA cert, and namespace file were
  mounted at the standard path (no `automountServiceAccountToken:
  false` set on the pod or its ServiceAccount).

Given no viable capability-based escape, pivoted to identity abuse:
extracted the mounted SA token and used it directly against the
Kubernetes API server (via a small PHP script, since curl/wget were
not present in this container — see `check.php` / `escalate.php`).

1. Queried `SelfSubjectRulesReview` to see what the stolen identity
   is actually authorized to do (`selfsubjectrulesreview.json`).
2. Attempted to create a privileged, host-mounting pod
   (`hostPID: true`, `privileged: true`, `hostPath: /` mounted into
   the container) — the standard Kubernetes container-breakout
   technique — directly via the Kubernetes API using the stolen
   token (`api-response.log`).

## Result: blocked at the authorization layer
The `SelfSubjectRulesReview` showed the `security-lab:default`
service account is restricted to self-introspection endpoints only
(`selfsubjectaccessreviews`, `selfsubjectrulesreviews`,
`selfsubjectreviews`) — the Kubernetes default when no RoleBinding
has been explicitly granted to the `default` service account in a
namespace.

The pod-creation attempt returned:

    HTTP/1.0 403 Forbidden
    "pods is forbidden: User \"system:serviceaccount:security-lab:default\"
     cannot create resource \"pods\" in API group \"\" in the namespace
     \"security-lab\""

The request was rejected by RBAC **before it ever reached the OPA
`NoPrivilegedContainers` / `NoPrivEsc` admission policies** — the
escalation attempt never got far enough to be evaluated by the
admission-control layer at all.

## No audit trail
The cluster's API server does not have `--audit-log-path` configured
(`/etc/kubernetes/manifests` contains no audit policy or log-path
flag). This escalation attempt produced no Kubernetes-native audit
record. The only evidence available is the direct HTTP response
captured by the attacking script itself. Flagged as a hardening gap
for future work.

## Implication
This is a case of **defense-in-depth working as intended through
redundancy, not sequence**: RBAC's least-privilege default was
sufficient on its own to stop a real container-breakout technique,
independent of whether the OPA admission layer would also have
caught it. It also demonstrates a limitation worth stating plainly:
this cluster currently has no audit logging, so denied escalation
attempts like this one leave no forensic trail beyond whatever the
attacker's own tooling happens to capture — a real detection gap,
distinct from the Falco gap already documented in Stage 4.
