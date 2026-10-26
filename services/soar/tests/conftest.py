from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace as NS

import pytest
from kubernetes.client.exceptions import ApiException

from k8s_soar.alert import parse
from k8s_soar.config import Settings
from k8s_soar.kube import Kube

FIXTURES = Path(__file__).parent / "fixtures"


def _merge_meta(meta: NS, patch: dict) -> None:
    for attr, key in (("labels", "labels"), ("annotations", "annotations")):
        if key in patch:
            current = dict(getattr(meta, attr) or {})
            for k, v in patch[key].items():
                if v is None:
                    current.pop(k, None)
                else:
                    current[k] = v
            setattr(meta, attr, current)


class FakeCore:
    def __init__(self, pods: dict[tuple[str, str], NS]):
        self.pods = pods
        self.patches: list[tuple[str, str, dict]] = []
        self.deleted: list[tuple[str, str]] = []
        self.conflicts_left = 0

    def read_namespaced_pod(self, name, namespace):
        try:
            return self.pods[(namespace, name)]
        except KeyError:
            raise ApiException(status=404, reason="Not Found") from None

    def patch_namespaced_pod(self, name, namespace, body):
        pod = self.read_namespaced_pod(name, namespace)
        meta = body.get("metadata", {})
        if self.conflicts_left:
            self.conflicts_left -= 1
            pod.metadata.resource_version = str(int(pod.metadata.resource_version) + 1)
            raise ApiException(status=409, reason="Conflict")
        if "resourceVersion" in meta and meta["resourceVersion"] != pod.metadata.resource_version:
            raise ApiException(status=409, reason="Conflict")
        _merge_meta(pod.metadata, meta)
        pod.metadata.resource_version = str(int(pod.metadata.resource_version) + 1)
        self.patches.append((namespace, name, body))
        return pod

    def delete_namespaced_pod(self, name, namespace):
        self.read_namespaced_pod(name, namespace)
        self.deleted.append((namespace, name))


class FakeApps:
    def __init__(self):
        self.scaled: list[tuple[str, str, str, dict]] = []
        self.replica_sets = {}

    def read_namespaced_replica_set(self, name, namespace):
        return self.replica_sets[(namespace, name)]

    def patch_namespaced_deployment_scale(self, name, namespace, body):
        self.scaled.append(("Deployment", namespace, name, body))


def make_pod(namespace="shop", name="web-5d9c-abcde", labels=None, annotations=None, owner="web-5d9c"):
    owners = [NS(kind="ReplicaSet", name=owner, controller=True)] if owner else []
    return NS(
        metadata=NS(
            name=name,
            namespace=namespace,
            labels=labels if labels is not None else {"app": "web", "pod-template-hash": "5d9c"},
            annotations=annotations or {},
            resource_version="1",
            owner_references=owners,
        )
    )


@pytest.fixture
def pod():
    return make_pod()


@pytest.fixture
def kube_fake(pod):
    core = FakeCore({("shop", "web-5d9c-abcde"): pod})
    apps = FakeApps()
    apps.replica_sets[("shop", "web-5d9c")] = NS(
        metadata=NS(owner_references=[NS(kind="Deployment", name="web", controller=True)]),
        spec=NS(selector=NS(match_labels={"app": "web", "pod-template-hash": "5d9c"}, match_expressions=None)),
    )
    return Kube(core=core, apps=apps, batch=None, networking=None)


@pytest.fixture
def settings():
    return Settings(trusted_namespaces=["kube-system", "falco"], dedup_minutes=10)


@pytest.fixture
def raw_alert() -> dict:
    return json.loads((FIXTURES / "falco_reverse_shell.json").read_text())


@pytest.fixture
def alert(raw_alert):
    a = parse(raw_alert)
    a.time = datetime.now(UTC)
    return a
