"""Argo Server API client: read case Workflows and resume the approval gate.

Decisions go through the same endpoints the Argo UI and `argo node set` /
`argo resume` use, so Argo stays the single source of truth for a case.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import httpx

SA_TOKEN = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")  # noqa: S105 - a path, not a secret
APPROVE_NODE = "displayName=approve"


@dataclass(frozen=True)
class ConsoleSettings:
    argo_server_url: str = "http://argo-workflows-server.argo.svc.cluster.local:2746"
    namespace: str = "k8s-soar"
    # Header set by an authenticating proxy (oauth2-proxy: X-Auth-Request-Email).
    # Empty: the analyst types a name, kept in a cookie.
    user_header: str = ""
    # Browser URL of Grafana. Empty: same host the console is opened on, port
    # 3000 (where `make grafana` listens).
    grafana_url: str = ""
    verify_tls: bool = True
    case_limit: int = 200
    timeout: float = 10.0


@lru_cache(maxsize=1)
def console_settings() -> ConsoleSettings:
    env = os.environ.get
    return ConsoleSettings(
        argo_server_url=env("CONSOLE_ARGO_SERVER_URL", ConsoleSettings.argo_server_url).rstrip("/"),
        namespace=env("CONSOLE_NAMESPACE") or env("POD_NAMESPACE") or "k8s-soar",
        user_header=env("CONSOLE_USER_HEADER", "").strip(),
        grafana_url=(env("CONSOLE_GRAFANA_URL") or env("SOAR_GRAFANA_EXTERNAL_URL") or "").rstrip("/"),
        verify_tls=env("CONSOLE_ARGO_VERIFY_TLS", "true").lower() == "true",
        case_limit=int(env("CONSOLE_CASE_LIMIT", "200") or 200),
    )


class ArgoError(RuntimeError):
    pass


class ArgoClient:
    def __init__(self, cfg: ConsoleSettings, transport: httpx.BaseTransport | None = None):
        self.cfg = cfg
        self._client = httpx.Client(
            base_url=cfg.argo_server_url, timeout=cfg.timeout, verify=cfg.verify_tls, transport=transport
        )

    def _headers(self) -> dict[str, str]:
        # Ignored in Argo's "server" auth mode; required in "client" mode.
        if SA_TOKEN.exists():
            return {"Authorization": f"Bearer {SA_TOKEN.read_text().strip()}"}
        return {}

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        try:
            resp = self._client.request(method, path, headers=self._headers(), **kwargs)
        except httpx.HTTPError as exc:
            raise ArgoError(f"Argo Server unreachable at {self.cfg.argo_server_url}: {exc}") from exc
        if resp.status_code >= 400:
            try:
                message = resp.json().get("message", resp.text)
            except ValueError:
                message = resp.text
            raise ArgoError(f"Argo Server {resp.status_code}: {message[:300]}")
        return resp.json() if resp.content else {}

    def list_workflows(self) -> list[dict[str, Any]]:
        data = self._request(
            "GET", f"/api/v1/workflows/{self.cfg.namespace}", params={"listOptions.limit": self.cfg.case_limit}
        )
        return data.get("items") or []

    def get_workflow(self, name: str) -> dict[str, Any]:
        return self._request("GET", f"/api/v1/workflows/{self.cfg.namespace}/{name}")

    def decide(self, name: str, action: str, message: str) -> None:
        """Equivalent of `argo node set --output-parameter action=...` then `argo resume`."""
        base = f"/api/v1/workflows/{self.cfg.namespace}/{name}"
        self._request(
            "PUT",
            f"{base}/set",
            json={
                "namespace": self.cfg.namespace,
                "name": name,
                "nodeFieldSelector": APPROVE_NODE,
                "outputParameters": json.dumps({"action": action}),
                "message": message,
            },
        )
        self._request(
            "PUT",
            f"{base}/resume",
            json={"namespace": self.cfg.namespace, "name": name, "nodeFieldSelector": APPROVE_NODE},
        )
