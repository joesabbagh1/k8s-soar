#!/usr/bin/env python3
"""Render per-chart values files from values.yaml + SOAR/Falco/Observability overlay."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: python3-yaml required (sudo apt install python3-yaml)", file=sys.stderr)
    sys.exit(1)

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
VALUES_FILE = ROOT / "values.yaml"
RULES_FILE = ROOT / "policies" / "falco" / "k8s-soar_rules.yaml"
DASHBOARD_FILE = ROOT / "observability" / "grafana" / "dashboard-k8s-soar-findings.json"
OUT_DIR = ROOT / ".generated"

MONITORING_NS = "monitoring"
KPS_RELEASE = "kube-prometheus-stack"
LOKI_URL = f"http://loki.{MONITORING_NS}.svc.cluster.local:3100"


def soar_enabled(values: dict) -> bool:
    """SOAR on by default (values.yaml); env K8S_SOAR_ENABLE_SOAR=0|1 overrides."""
    soar_env = os.environ.get("K8S_SOAR_ENABLE_SOAR")
    if soar_env is not None:
        return soar_env == "1"
    return bool((values.get("soar") or {}).get("responder", {}).get("enabled", True))


def observability_enabled(values: dict) -> bool:
    """Observability on by default; env K8S_SOAR_ENABLE_OBSERVABILITY=0|1 overrides."""
    obs_env = os.environ.get("K8S_SOAR_ENABLE_OBSERVABILITY")
    if obs_env is not None:
        return obs_env == "1"
    return bool((values.get("observability") or {}).get("enabled", True))


def load_yaml(path: Path) -> dict:
    with path.open() as fh:
        return yaml.safe_load(fh) or {}


def dump_yaml(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        yaml.safe_dump(data, fh, default_flow_style=False, sort_keys=False)


def deep_merge(base: dict, overlay: dict) -> dict:
    merged = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def apply_falco_observability(falco_values: dict, enable_obs: bool) -> None:
    if not enable_obs:
        return

    falco_values["metrics"] = deep_merge(
        falco_values.get("metrics") or {},
        {
            "enabled": True,
            "interval": "15m",
            "rulesCountersEnabled": True,
        },
    )
    falco_values["serviceMonitor"] = deep_merge(
        falco_values.get("serviceMonitor") or {},
        {
            "enabled": True,
            "labels": {"release": KPS_RELEASE},
        },
    )

    sidekick = falco_values.setdefault("falcosidekick", {})
    sidekick_cfg = sidekick.setdefault("config", {})
    sidekick_cfg["loki"] = {
        "hostport": LOKI_URL,
        "format": "json",
        "minimumpriority": "notice",
    }
    sidekick["serviceMonitor"] = deep_merge(
        sidekick.get("serviceMonitor") or {},
        {
            "enabled": True,
            "additionalLabels": {"release": KPS_RELEASE},
        },
    )
    sidekick["prometheusRules"] = deep_merge(
        sidekick.get("prometheusRules") or {},
        {
            "enabled": True,
            "additionalLabels": {"release": KPS_RELEASE},
        },
    )


def build_loki_values(obs: dict) -> dict:
    loki_cfg = dict(obs.get("loki") or {})
    loki_inner = {k: v for k, v in loki_cfg.items() if k not in ("read", "write", "backend", "singleBinary", "deploymentMode")}
    return {
        "deploymentMode": loki_cfg.get("deploymentMode", "SingleBinary"),
        "loki": loki_inner,
        "singleBinary": loki_cfg.get("singleBinary") or {"replicas": 1},
        "read": loki_cfg.get("read") or {"replicas": 0},
        "write": loki_cfg.get("write") or {"replicas": 0},
        "backend": loki_cfg.get("backend") or {"replicas": 0},
    }


def build_promtail_values() -> dict:
    return {
        "config": {
            "clients": [{"url": f"{LOKI_URL}/loki/api/v1/push"}],
        },
        "resources": {
            "requests": {"cpu": "50m", "memory": "64Mi"},
            "limits": {"memory": "128Mi"},
        },
    }


def build_kube_prometheus_stack_values(obs: dict) -> dict:
    kps = dict(obs.get("kubePrometheusStack") or {})
    grafana_cfg = dict(kps.get("grafana") or {})
    prometheus_cfg = dict(kps.get("prometheus") or {})
    alertmanager_cfg = dict(kps.get("alertmanager") or {"enabled": True})

    dashboard = {}
    if DASHBOARD_FILE.is_file():
        dashboard = json.loads(DASHBOARD_FILE.read_text())

    grafana_values = deep_merge(
        {
            "enabled": True,
            "defaultDashboardsEnabled": True,
            "sidecar": {
                "dashboards": {"enabled": True, "label": "grafana_dashboard"},
            },
            "dashboardProviders": {
                "dashboardproviders.yaml": {
                    "apiVersion": 1,
                    "providers": [
                        {
                            "name": "k8s-soar",
                            "orgId": 1,
                            "folder": "k8s-soar",
                            "type": "file",
                            "disableDeletion": False,
                            "editable": True,
                            "options": {"path": "/var/lib/grafana/dashboards/k8s-soar"},
                        }
                    ],
                }
            },
            "dashboards": {
                "k8s-soar": {
                    "k8s-soar-findings": dashboard,
                }
            },
            "alerting": {
                "rules.yaml": {
                    "apiVersion": 1,
                    "groups": [
                        {
                            "orgId": 1,
                            "name": "k8s-soar",
                            "folder": "k8s-soar",
                            "interval": "1m",
                            "rules": [
                                {
                                    "uid": "k8ssoar-finding",
                                    "title": "K8sSoar Falco finding",
                                    "condition": "C",
                                    "data": [
                                        {
                                            "refId": "A",
                                            "relativeTimeRange": {"from": 300, "to": 0},
                                            "datasourceUid": "loki",
                                            "model": {
                                                "editorMode": "code",
                                                "expr": 'sum(count_over_time({namespace=~"falco|monitoring"} |~ "K8sSoar" [5m]))',
                                                "queryType": "instant",
                                                "refId": "A",
                                            },
                                        },
                                        {
                                            "refId": "C",
                                            "relativeTimeRange": {"from": 0, "to": 0},
                                            "datasourceUid": "__expr__",
                                            "model": {
                                                "conditions": [
                                                    {
                                                        "evaluator": {"params": [0], "type": "gt"},
                                                        "operator": {"type": "and"},
                                                        "query": {"params": ["C"]},
                                                        "reducer": {"params": [], "type": "last"},
                                                        "type": "query",
                                                    }
                                                ],
                                                "expression": "A",
                                                "refId": "C",
                                                "type": "threshold",
                                            },
                                        },
                                    ],
                                    "noDataState": "OK",
                                    "execErrState": "Alerting",
                                    "for": "0s",
                                    "annotations": {
                                        "summary": "A k8s-soar Falco rule fired in the last 5 minutes.",
                                        "description": "Check the k8s-soar — Falco Findings dashboard and security-lab namespace.",
                                    },
                                    "labels": {"severity": "warning", "team": "k8s-soar"},
                                }
                            ],
                        }
                    ],
                }
            },
        },
        grafana_cfg,
    )

    prom_spec = deep_merge(
        {
            "serviceMonitorSelectorNilUsesHelmValues": True,
            "podMonitorSelectorNilUsesHelmValues": True,
            "ruleSelectorNilUsesHelmValues": True,
        },
        (prometheus_cfg.get("prometheusSpec") or {}),
    )

    return {
        "grafana": grafana_values,
        "prometheus": deep_merge({"prometheusSpec": prom_spec}, prometheus_cfg),
        "alertmanager": alertmanager_cfg,
        "defaultRules": {
            "create": True,
            "rules": {
                "alertmanager": True,
                "etcd": False,
                "kubeScheduler": False,
                "kubeControllerManager": False,
            },
        },
    }


def main() -> None:
    values = load_yaml(VALUES_FILE)
    rules_text = RULES_FILE.read_text()

    enable_soar = soar_enabled(values)
    enable_obs = observability_enabled(values)
    obs_cfg = values.get("observability") or {}

    falco_values = dict(values.get("falco") or {})
    falco_values.pop("enabled", None)
    falco_values.setdefault("customRules", {})["k8s-soar_rules.yaml"] = rules_text
    falco_values.setdefault("falcosidekick", {})["enabled"] = enable_soar or enable_obs
    if not enable_soar:
        falco_values.setdefault("falcosidekick", {}).setdefault("config", {}).pop("webhook", None)
    apply_falco_observability(falco_values, enable_obs)

    soar_values = dict(values.get("soar") or {})

    parent_values = {
        "policies": values.get("policies", {"enabled": False}),
        "lab": values.get("lab", {"enabled": False}),
        "soar": soar_values,
        "observability": {
            "enabled": enable_obs,
            "namespace": obs_cfg.get("namespace", MONITORING_NS),
        },
        "cilium": {"enabled": False},
        "falco": {"enabled": False},
        "tetragon": {"enabled": False},
        "kyverno": {"enabled": False},
        "loki": {"enabled": False},
        "promtail": {"enabled": False},
        "kube-prometheus-stack": {"enabled": False},
    }

    for key in ("cilium", "tetragon", "kyverno"):
        dump_yaml(OUT_DIR / f"{key}-values.yaml", values.get(key) or {})

    dump_yaml(OUT_DIR / "falco-values.yaml", falco_values)
    dump_yaml(OUT_DIR / "k8s-soar-values.yaml", parent_values)

    if enable_obs:
        dump_yaml(OUT_DIR / "loki-values.yaml", build_loki_values(obs_cfg))
        dump_yaml(OUT_DIR / "promtail-values.yaml", build_promtail_values())
        dump_yaml(
            OUT_DIR / "kube-prometheus-stack-values.yaml",
            build_kube_prometheus_stack_values(obs_cfg),
        )

    dump_yaml(
        OUT_DIR / "helm-values.yaml",
        parent_values
        | {
            "falco": falco_values,
            "soar": parent_values["soar"],
            "observability": parent_values["observability"],
        },
    )

    print(f">>> Wrote stack values to {OUT_DIR}/")
    if enable_obs:
        print(">>> Observability enabled (Grafana + Prometheus + Loki)")


if __name__ == "__main__":
    main()
