# k8s-soar

> **Kubernetes Security Orchestration, Automation & Response**
> Thesis project — Falco + Tetragon + Kyverno environment bootstrap

[![Publish Helm Chart](https://github.com/joesabbagh1/k8s-soar/actions/workflows/helm-publish.yml/badge.svg)](https://github.com/joesabbagh1/k8s-soar/actions/workflows/helm-publish.yml)

---

## Overview

`k8s-soar` is a Helm umbrella chart that bootstraps a complete threat detection and policy enforcement stack on any Kubernetes cluster:

| Component | Role | Mechanism |
|-----------|------|-----------|
| **Falco** | Runtime threat detection | Syscall interception via modern eBPF |
| **Tetragon** | Kernel-level enforcement | eBPF TracingPolicies (Cilium sub-project) |
| **Kyverno** | Admission policy engine | Kubernetes admission webhook |

## Prerequisites

- Kubernetes ≥ 1.28
- Helm ≥ 3.14
- Nodes with eBPF support (kernel ≥ 5.10 recommended)
- If using your homelab: Cilium is already installed — set `cilium.enabled=false` (default)

## Install from GHCR

```bash
helm install k8s-soar oci://ghcr.io/joesabbagh1/k8s-soar \
  --version 0.1.0 \
  --namespace k8s-soar \
  --create-namespace
```

## Install from source

```bash
# 1. Add dependency repos
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo add cilium         https://helm.cilium.io/
helm repo add kyverno        https://kyverno.github.io/kyverno/
helm repo update

# 2. Fetch sub-charts
helm dependency update ./k8s-soar

# 3. Install
helm install k8s-soar ./k8s-soar \
  --namespace k8s-soar \
  --create-namespace
```

## Configuration

All options are in [`values.yaml`](./values.yaml). Key overrides:

```yaml
# Disable a component (e.g. Kyverno)
kyverno:
  enabled: false

# Switch Kyverno to enforce mode (blocks policy violations)
kyverno:
  validationFailureAction: Enforce

# Point Falco sidekick to a Slack webhook
falco:
  falcosidekick:
    config:
      slack:
        webhookurl: "https://hooks.slack.com/..."
```

## Verify

```bash
kubectl get pods -n falco
kubectl get pods -n tetragon
kubectl get pods -n kyverno

# Stream Falco alerts
kubectl logs -n falco -l app.kubernetes.io/name=falco -f

# Stream Tetragon kernel events
kubectl exec -n tetragon ds/tetragon -- tetra getevents -o compact

# List Kyverno policies
kubectl get cpol,pol -A
```

## Publishing

The chart is automatically built and pushed to GHCR on every push to `main`.
To publish a release version, push a tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

This triggers the workflow to publish `ghcr.io/joesabbagh1/k8s-soar:0.1.0`.

## Roadmap

- [ ] Phase 1: Environment bootstrap (this chart)
- [ ] Phase 2: Falco rules library (Kyverno ClusterPolicies + Falco custom rules)
- [ ] Phase 3: SOAR response workflow (Detect → Isolate automation)

## License

MIT
