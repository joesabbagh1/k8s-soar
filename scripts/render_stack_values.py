#!/usr/bin/env python3
"""Render per-chart values files from values.yaml + SOAR/Falco overlay."""
from __future__ import annotations

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
OUT_DIR = ROOT / ".generated"
ENABLE_SOAR = os.environ.get("K8S_SOAR_ENABLE_SOAR", "0") == "1"


def load_yaml(path: Path) -> dict:
    with path.open() as fh:
        return yaml.safe_load(fh) or {}


def dump_yaml(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        yaml.safe_dump(data, fh, default_flow_style=False, sort_keys=False)


def main() -> None:
    values = load_yaml(VALUES_FILE)
    rules_text = RULES_FILE.read_text()

    falco_values = dict(values.get("falco") or {})
    falco_values.setdefault("customRules", {})["k8s-soar_rules.yaml"] = rules_text
    if ENABLE_SOAR:
        falco_values.setdefault("falcosidekick", {})["enabled"] = True

    parent_values = {
        "policies": values.get("policies", {"enabled": False}),
        "lab": values.get("lab", {"enabled": False}),
        "soar": values.get("soar", {"responder": {"enabled": False}}),
        "cilium": {"enabled": False},
        "falco": {"enabled": False},
        "tetragon": {"enabled": False},
        "kyverno": {"enabled": False},
    }
    if ENABLE_SOAR:
        parent_values.setdefault("soar", {}).setdefault("responder", {})["enabled"] = True

    for key in ("cilium", "tetragon", "kyverno"):
        dump_yaml(OUT_DIR / f"{key}-values.yaml", values.get(key) or {})

    dump_yaml(OUT_DIR / "falco-values.yaml", falco_values)
    dump_yaml(OUT_DIR / "k8s-soar-values.yaml", parent_values)

    # Legacy overlay path used by docs/CI
    dump_yaml(OUT_DIR / "helm-values.yaml", parent_values | {
        "falco": falco_values,
        "soar": parent_values["soar"],
    })

    print(f">>> Wrote stack values to {OUT_DIR}/")


if __name__ == "__main__":
    main()
