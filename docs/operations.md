# Operations

## Install paths

| Situation | Command |
|-----------|---------|
| Bare-metal / VMs, nothing installed | `cd deploy/ansible && ./setup.sh` (kubeadm → helmfile) |
| kubeadm done, no CNI | `make deploy` (installs Cilium first) |
| Cluster already running Cilium | set `cilium.install: false` in the profile, `make deploy` |
| Cluster with another CNI | possible, but quarantine needs Cilium: pods get labelled, not isolated |

Requirements on the operator machine: `kubectl`, `helm` ≥ 3.15, `helmfile` ≥ 1.0 with
`helm-diff` (`helmfile init`). `make preflight` checks all of it. Ansible installs pinned helm
and helmfile into `~/.local/bin`.

Images: the chart pulls `ghcr.io/joesabbagh1/k8s-soar-actions` and `k8s-soar-agent` at the
chart's `appVersion`. Before the first release is published (or for local changes), build and
push your own: `make push REGISTRY=ghcr.io/<you>` and set `k8sSoar.image.registry`.

## Configuration map

| What | Where |
|------|-------|
| Response mode, AI provider/model, lab, external URLs | `deploy/profiles/<env>.yaml` → `k8sSoar` |
| Everything else in the k8s-soar chart | `charts/k8s-soar/values.yaml` (override under `k8sSoar` in the profile) |
| Component settings (Falco, Argo, Loki, ...) | `deploy/values/<release>.yaml.gotmpl` |
| Component versions | `deploy/helmfile.yaml.gotmpl` |
| Secrets | `deploy/secrets.env` → `make secrets` |
| Detection rules | `charts/k8s-soar/files/falco-rules/` |

## Day-2

```bash
make diff                 # what would change
make deploy               # apply everything (idempotent)
make deploy-soar          # only rules/policies/response/agent — fast
make status               # health check
make cases                # recent cases
make quarantined          # quarantined pods
make console             # analyst console: review and decide cases (port 8081)
make grafana             # Grafana on port 3000; the console's log links open here
make argo-ui              # Argo (raw workflow view); all three listen on all interfaces
```

**Upgrading a component:** bump its `version:` in `deploy/helmfile.yaml.gotmpl`, read the
upstream changelog, `make diff`, `make deploy`.

## Observability

Grafana folder **k8s-soar**:

- **k8s-soar — Findings**: Falco findings by rule, rule match counters, live finding log.
- **k8s-soar — Response**: cases opened, pods contained, time-to-contain p95, currently
  quarantined pods, AI verdicts, workflow status, responder logs.

Loki has Falco events (`{namespace="falco"}`), Tetragon events (`{container="export-stdout"}`),
case step logs (`{namespace="k8s-soar", container="main"}`) and agent audit lines.

Alerting: a Grafana rule fires on any k8s-soar finding; Alertmanager sends `severity=critical`
cluster alerts to the response pipeline as notify cases.

## Troubleshooting

| Symptom | Check |
|---------|-------|
| No cases at all | `kubectl logs -n falco deploy/falco-falcosidekick` (webhook errors?), `kubectl get pods -n k8s-soar` (eventsource + sensor running?), `kubectl logs -n k8s-soar -l sensor-name=soar-router` |
| Falco rules not firing | `kubectl logs -n falco -l app.kubernetes.io/name=falco -c falco \| grep -i k8s-soar`; plugins missing → `-c falcoctl-artifact-install` logs (needs ghcr.io access) |
| Case stuck Pending | step image pull (`kubectl describe pod -n k8s-soar <step pod>`), wrong `image.registry` |
| Pod labelled but not isolated | `kubectl get ccnp k8s-soar-quarantine`, `cilium-dbg policy get` on the node |
| Quarantined container restarts | probes from the node blocked: check host entity allowed in the policy |
| Pod CrashLoops with `couldn't initialize inotify: too many open files` | node inotify limit: `sudo sysctl -w fs.inotify.max_user_instances=8192 fs.inotify.max_user_watches=524288` (Ansible sets it persistently), then delete the pod |
| Console shows "Argo Server unreachable" | `kubectl get pods -n argo`; `console.argoServerUrl`; with `argo.authMode: client` check the soar-console Role |
| AI verdict always `unavailable` | `kubectl logs -n k8s-soar deploy/soar-agent`, `GET /config` shows `api_key_configured` |
| Can't remove quarantine label | expected (Kyverno). Resume the case with `release-quarantine` or use an admin identity |
