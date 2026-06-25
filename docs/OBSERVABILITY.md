# Observability

k8s-soar ships Grafana, Prometheus, and Loki as **split Helm releases** in the `monitoring` namespace. They complement Falco detection with dashboards and alerts over findings and stack metrics.

## Why Loki?

| Store | Best for |
|-------|----------|
| **Prometheus** | Alert rates, rule counters, resource usage, SLO-style thresholds |
| **Loki** | Full Falco JSON payloads — searchable rule names, namespaces, pods, output text |

Prometheus alone cannot replace log search for incident review. Loki (fed by **falcosidekick** and **Promtail**) is the right store for “what exactly happened?” during scenarios.

## Data flow

```text
Falco (JSON) ──► falcosidekick ──► Loki ──► Grafana dashboards / alerts
              └──► webhook ──► SOAR responder (unchanged)

Falco / sidekick / responder pod logs ──► Promtail ──► Loki

Falco metrics ──► ServiceMonitor ──► Prometheus ──► Grafana
falcosidekick metrics ──► ServiceMonitor ──► Prometheus
```

## Access Grafana

```bash
./scripts/port-forward-grafana.sh
```

Default credentials: `admin` / `k8s-soar` (set `observability.kubePrometheusStack.grafana.adminPassword` in `values.yaml`).

Open the **k8s-soar — Falco Findings** dashboard (folder `k8s-soar`).

## Alerts

Two layers are provisioned:

1. **Grafana (Loki)** — `K8sSoar Falco finding` fires when any log line matches `K8sSoar` in the last 5 minutes.
2. **Prometheus (falcosidekick)** — built-in `PrometheusRule` objects for Falco priority rates when falcosidekick is enabled.

Tune or add rules under **Alerting** in Grafana, or extend `observability.kubePrometheusStack` in `values.yaml`.

## Disable

```yaml
observability:
  enabled: false
```

```bash
K8S_SOAR_ENABLE_OBSERVABILITY=0 ./scripts/install.sh
```

SOAR can stay enabled without observability; falcosidekick is only kept for Loki when observability is on (or for the webhook when SOAR is on).

## After scenarios

Run a scenario, then in Grafana:

- **Logs panel** — filter `{namespace="falco"} |= "K8sSoar"`
- **Stat panel** — Prometheus `falcosecurity_falco_rules_matches_total{rule=~"K8sSoar.*"}`

Correlate with SOAR quarantine labels:

```bash
kubectl get pods -n security-lab -l security.quarantine=true
```
