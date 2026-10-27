"""HTTP server of the soar-console Deployment.

GET  /                      case list (open cases first)
GET  /cases/{name}          case page: what happened, what k8s-soar did, evidence, AI verdict
POST /cases/{name}/decide   analyst decision -> resumes the case's approval gate
GET  /api/cases             case list as JSON
GET  /healthz
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Annotated
from urllib.parse import quote, urlparse

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from k8s_soar import grafana
from k8s_soar.config import settings

from . import cases
from .argo import ArgoClient, ArgoError, console_settings

log = logging.getLogger("k8s_soar.console")
audit = logging.getLogger("k8s_soar.audit")

app = FastAPI(title="k8s-soar console", version="0.4.3", docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
templates.env.globals["ago"] = cases.ago
templates.env.globals["offset"] = cases.offset

ANALYST_COOKIE = "soar_analyst"
_CASE_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]{0,252}$")
FILTERS = {
    "open": {cases.AWAITING, cases.IN_PROGRESS, cases.FAILED},
    "closed": {cases.CLOSED},
    "all": {cases.AWAITING, cases.IN_PROGRESS, cases.FAILED, cases.CLOSED, cases.SKIPPED},
}


def argo() -> ArgoClient:
    client = getattr(app.state, "argo", None)
    if client is None:
        client = app.state.argo = ArgoClient(console_settings())
    return client


def _check_name(name: str) -> str:
    if not _CASE_NAME.match(name):
        raise HTTPException(404, "no such case")
    return name


def _same_origin(request: Request) -> bool:
    """Reject cross-site form posts (CSRF): browsers always send Origin on POST."""
    origin = request.headers.get("origin")
    if not origin or origin == "null":
        return origin is None
    return urlparse(origin).netloc == request.headers.get("host", "")


def _analyst(request: Request, typed: str) -> str:
    header = console_settings().user_header
    if header and request.headers.get(header):
        return request.headers[header].strip()[:100]
    return typed.strip()[:100]


def _page(request: Request, template: str, **context) -> HTMLResponse:
    cfg = console_settings()
    context.setdefault("error", "")
    return templates.TemplateResponse(
        request,
        template,
        {
            "mode": settings().mode,
            "proxy_user": request.headers.get(cfg.user_header, "") if cfg.user_header else "",
            "analyst": request.cookies.get(ANALYST_COOKIE, ""),
            **context,
        },
    )


def _grafana_base(request: Request) -> str:
    configured = console_settings().grafana_url
    if configured:
        return configured
    host = (request.url.hostname or "localhost").strip("[]")
    return f"{request.url.scheme}://{host}:3000"


def _load_cases() -> list[cases.Case]:
    return sorted((cases.from_workflow(wf) for wf in argo().list_workflows()), key=cases.sort_key)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def case_list(request: Request, show: str = "open") -> HTMLResponse:
    show = show if show in FILTERS else "open"
    error, all_cases = "", []
    try:
        all_cases = _load_cases()
    except ArgoError as exc:
        error = str(exc)
    counts = {key: sum(1 for c in all_cases if c.status in statuses) for key, statuses in FILTERS.items()}
    counts["awaiting"] = sum(1 for c in all_cases if c.awaiting)
    visible = [c for c in all_cases if c.status in FILTERS[show]]
    return _page(request, "cases.html", cases=visible, show=show, counts=counts, error=error)


@app.get("/cases/{name}", response_class=HTMLResponse)
def case_page(request: Request, name: str, decided: str = "") -> HTMLResponse:
    try:
        case = cases.from_workflow(argo().get_workflow(_check_name(name)))
    except ArgoError as exc:
        if "404" in str(exc):
            raise HTTPException(404, "no such case") from exc
        return _page(request, "cases.html", cases=[], show="open", counts={}, error=str(exc))
    base = _grafana_base(request)
    at = case.alert.time if case.alert else case.created
    log_links = (
        grafana.case_log_links(base, at, case.alert.namespace, case.alert.pod, case.name) if case.alert and at else []
    )
    dashboard = grafana.dashboard_url(base, "k8s-soar-response", at) if at else ""
    raw_alert = json.dumps(case.alert.model_dump(mode="json"), indent=2) if case.alert else ""
    return _page(
        request,
        "case.html",
        case=case,
        log_links=log_links,
        dashboard=dashboard,
        grafana_base=base,
        raw_alert=raw_alert,
        decided=decided,
    )


@app.post("/cases/{name}/decide")
def decide(
    request: Request,
    name: str,
    action: Annotated[str, Form()],
    comment: Annotated[str, Form()] = "",
    analyst: Annotated[str, Form()] = "",
) -> Response:
    name = _check_name(name)
    if not _same_origin(request):
        raise HTTPException(403, "cross-site request refused")
    who = _analyst(request, analyst)
    if not who:
        raise HTTPException(400, "enter your name so the decision is attributed")
    case = cases.from_workflow(argo().get_workflow(name))
    if not case.awaiting:
        raise HTTPException(409, "this case is not waiting for a decision (already decided?)")
    if action not in {choice.action for choice in case.choices}:
        raise HTTPException(400, f"action {action!r} is not available for this case")

    comment = " ".join(comment.split())[:500]
    message = f"{action} by {who}" + (f": {comment}" if comment else "")
    try:
        argo().decide(name, action, message)
    except ArgoError as exc:
        raise HTTPException(502, str(exc)) from exc
    audit.info(
        json.dumps(
            {
                "event": "decision",
                "case": name,
                "action": action,
                "analyst": who,
                "comment": comment,
                "recommended": case.recommended,
                "rule": case.alert.rule if case.alert else "",
                "namespace": case.alert.namespace if case.alert else "",
                "pod": case.alert.pod if case.alert else "",
            }
        )
    )
    response = RedirectResponse(f"/cases/{quote(name)}?decided={quote(action)}", status_code=303)
    response.set_cookie(ANALYST_COOKIE, who, max_age=30 * 86400, httponly=True, samesite="strict")
    return response


@app.get("/api/cases")
def api_cases() -> list[dict[str, object]]:
    return [
        {
            "name": c.name,
            "status": c.status,
            "status_label": c.status_label,
            "rule": c.alert.rule if c.alert else "",
            "severity": c.severity,
            "workload": c.workload,
            "created": c.created.isoformat() if c.created else None,
            "contained": c.contained,
            "recommended": c.recommended,
            "decision": c.chosen_action,
        }
        for c in _load_cases()
    ]


def main() -> None:
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))  # noqa: S104


if __name__ == "__main__":
    main()
