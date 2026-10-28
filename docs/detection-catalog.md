# Detection catalog

All k8s-soar Falco rules ignore the **trusted namespaces** (`trustedNamespaces` in
`charts/k8s-soar/values.yaml`) and images listed in `k8s_soar_allowed_images`.

Response column: **contain** = quarantined immediately, then triage + notify + approval gate;
**notify** = triage + notify + approval gate, no automatic change.

## Falco rules (`charts/k8s-soar/files/falco-rules/`)

| Rule | Priority | MITRE | Response | Typical false positives |
|------|----------|-------|----------|-------------------------|
| K8sSoar Reverse Shell | Critical | T1059.004 | contain | none known (stdio on a socket) |
| K8sSoar Shell Outbound Connection | Critical | T1071 | contain | scripts using `/dev/tcp` health checks |
| K8sSoar Drifted Binary Executed | Critical | T1105 | contain | images that download plugins/binaries at start → `k8s_soar_allowed_images` |
| K8sSoar Service Account Token Read By Shell Tool | Critical | T1552.007 | contain | debugging with `kubectl exec ... cat token` |
| K8sSoar Sensitive File Read | Critical | T1003.008 | contain | images whose entrypoint reads /etc/shadow (rare) |
| K8sSoar Container Escape Tooling | Critical | T1611 | contain | init containers that `mount` |
| K8sSoar Crypto Miner Execution | Critical | T1496 | contain | — |
| K8sSoar Crypto Mining Pool Connection | Critical | T1496 | contain | apps on ports 3333/4444/5555/7777/8888/9999 (port list is broad; tune `k8s_soar_miner_ports`) |
| K8sSoar Lateral Movement To Pod | Critical | T1021 | contain | shell scripts that `wget`/`curl` a ClusterIP or pod IP (health checks) |
| K8sSoar API Server Access From Shell Tool | Error | T1613 | notify | scripted health checks with curl |
| K8sSoar Write Below Binary Directory | Error | T1036 | notify | images that self-update |
| K8sSoar Terminal Shell In Container | Warning | T1059 | notify | interactive debugging |
| K8sSoar Package Manager In Running Container | Warning | T1072 | notify | images installing packages at start (anti-pattern); queries such as `apk manifest` are ignored |
| K8sSoar Cloud Metadata Access | Warning | T1552.005 | notify | cloud SDKs (IRSA, workload identity) |
| K8sSoar Network Recon Tool | Warning | T1046 | notify | network debug images (netshoot) |
| K8sSoar Kubernetes Client In Container | Warning | T1613 | notify | CI runners, operators with kubectl |

Stock Falco rules (falco-rules v4) also run (`rule_matching: all`). Any stock rule at
**Critical** or above opens a notify case.

### Tuning

- **Allow an image**: append to `k8s_soar_allowed_images` (prefix match on repository).
- **Trust a namespace**: add to `trustedNamespaces` in your profile (`k8sSoar.trustedNamespaces`);
  it feeds the Falco list, Kyverno exclusions and the responder guard.
- **Change routing**: edit the rule's `soar_contain`/`soar_notify` tag.
- **Per-rule exceptions**: use Falco `exceptions:` or `override: condition: append` in your own
  rules file next to these.

Changes are applied by `make deploy-soar`; Falco hot-reloads the ConfigMap (no restart).

## Tetragon policies (`templates/detection/tetragon.yaml`)

| Policy | Mode | Purpose |
|--------|------|---------|
| k8s-soar-observe-sensitive-files | observe | access to shadow/sudoers/ssh keys/SA tokens |
| k8s-soar-observe-egress | observe | TCP connects outside internal CIDRs |
| k8s-soar-observe-namespace-escapes | observe | setns / unshare / mount syscalls |
| k8s-soar-enforce-sensitive-writes | **enforce (SIGKILL)** | writes to /etc/shadow, sudoers, binaries — only pods labelled `k8s-soar.io/enforce=true` |

Observe events land in Loki (`{container="export-stdout"}`) and are attached to cases by the
enrich step and the AI agent.

## Kyverno policies (`templates/detection/kyverno.yaml`)

| Policy | Default | Covers |
|--------|---------|--------|
| k8s-soar-pod-security-baseline | Audit | privileged, host namespaces/ports/paths, dangerous capabilities |
| k8s-soar-pod-security-restricted | Audit | non-root, drop ALL, seccomp, no privilege escalation |
| k8s-soar-disallow-latest-tag | Audit | `:latest` / untagged images |
| k8s-soar-require-resource-limits | Audit | memory limits + CPU requests (bounds resource hijacking) |
| k8s-soar-restrict-sa-token-automount | Disabled | token automount |
| k8s-soar-protect-quarantine | **Enforce** | only the responder or admins can lift a quarantine |
| k8s-soar-responder-scope | **Enforce** | responder can never modify trusted namespaces |

Review with `kubectl get policyreport -A`, then switch policies to `Enforce` in your profile.
