# Stage 3 — Discovery (T1613)

## Action
Using the service-account token stolen in Stage 2, attempted to list
pods in the `security-lab` namespace via the Kubernetes API from
inside the compromised DVWA pod (PHP `file_get_contents` against
`https://kubernetes.default.svc/api/v1/namespaces/security-lab/pods`).

## Result: attack blocked by RBAC
The default service account for `security-lab` has no RBAC bindings
granting pod-list permissions. The API server correctly rejected the
request with 403 Forbidden (see rbac-denial.log). This demonstrates
that even a successfully stolen token does not grant lateral-movement
capability in this cluster configuration — RBAC hardening acts as a
second layer of defense independent of runtime detection.

## Detection layer
Falco's stock rule "Contact K8S API Server From Container" (which does
NOT depend on k8s.ns.name and has fired reliably for other pods
throughout this session) did not fire for this specific request from
the DVWA pod. This is consistent with, and further evidence for, the
detection gap already documented in falco-detection-gap.md — it
appears not to be limited to the four custom k8s-soar rules, but
extends to at least one stock rule as well when the source pod is
one that was created after Falco's own startup.
