"""Thin wrapper around the Kubernetes client so it can be swapped out in tests."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

__all__ = ["ApiException", "Kube", "kube"]


@dataclass
class Kube:
    core: client.CoreV1Api
    apps: client.AppsV1Api
    batch: client.BatchV1Api
    networking: client.NetworkingV1Api


@lru_cache(maxsize=1)
def kube() -> Kube:
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return Kube(
        core=client.CoreV1Api(),
        apps=client.AppsV1Api(),
        batch=client.BatchV1Api(),
        networking=client.NetworkingV1Api(),
    )


def is_not_found(exc: ApiException) -> bool:
    return exc.status == 404


def is_conflict(exc: ApiException) -> bool:
    return exc.status == 409
