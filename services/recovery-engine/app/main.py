from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException
from kubernetes import client, config
from pydantic import BaseModel

from services.shared.observability import install_observability, observe_event

app = FastAPI(title="recovery-engine")
logger = install_observability(app, "recovery-engine")
timeline: list[dict] = []
NAMESPACE = os.getenv("PLATFORM_NAMESPACE", "chaos-loop")
DEFAULT_TARGET_NAMESPACES = [
    item.strip() for item in os.getenv("TARGET_NAMESPACES", NAMESPACE).split(",") if item.strip()
]
INVENTORY_URL = os.getenv("INVENTORY_URL", "http://inventory-service:8000")


def load_k8s() -> tuple[client.AppsV1Api, client.CoreV1Api, client.NetworkingV1Api]:
    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()
    return client.AppsV1Api(), client.CoreV1Api(), client.NetworkingV1Api()


class RecoveryRequest(BaseModel):
    action: str
    target: str | None = None
    namespace: str | None = None
    container_name: str | None = None
    replicas: int | None = None
    service_name: str | None = None
    selector_value: str | None = None
    reason: str | None = None


def add_timeline(entry: dict) -> None:
    timeline.append(entry)
    del timeline[:-200]


def target_namespace(request: RecoveryRequest) -> str:
    return request.namespace or DEFAULT_TARGET_NAMESPACES[0]


def target_namespaces(core_api: client.CoreV1Api) -> list[str]:
    if DEFAULT_TARGET_NAMESPACES == ["*"] or DEFAULT_TARGET_NAMESPACES == ["all"]:
        return [item.metadata.name for item in core_api.list_namespace().items]
    return DEFAULT_TARGET_NAMESPACES


def patch_env(containers: list[client.V1Container], container_name: str | None, env_name: str, env_value: str) -> list[dict]:
    patches = []
    for container in containers:
        if container_name and container.name != container_name:
            continue
        env = [{"name": item.name, "value": item.value} for item in (container.env or []) if item.name != env_name]
        env.append({"name": env_name, "value": env_value})
        patches.append({"name": container.name, "env": env})
    return patches


@app.post("/recover")
async def recover(request: RecoveryRequest) -> dict:
    apps_api, _, net_api = load_k8s()
    namespace = target_namespace(request)
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "action": request.action,
        "target": request.target,
        "namespace": namespace,
        "reason": request.reason,
    }
    try:
        if request.action == "restart_deployment":
            patch = {
                "spec": {
                    "template": {
                        "metadata": {
                            "annotations": {
                                "kubectl.kubernetes.io/restartedAt": datetime.now(timezone.utc).isoformat()
                            }
                        }
                    }
                }
            }
            apps_api.patch_namespaced_deployment(request.target, namespace, patch)
        elif request.action == "scale_deployment":
            if request.replicas is None:
                raise HTTPException(status_code=400, detail="replicas_required")
            patch = {"spec": {"replicas": request.replicas}}
            apps_api.patch_namespaced_deployment_scale(request.target, namespace, patch)
        elif request.action == "reroute_service":
            if not request.service_name or not request.selector_value:
                raise HTTPException(status_code=400, detail="service_name_and_selector_value_required")
            patch = {"spec": {"selector": {"app": request.service_name, "lane": request.selector_value}}}
            client.CoreV1Api().patch_namespaced_service(request.service_name, namespace, patch)
        elif request.action == "restore_cache":
            async with httpx.AsyncClient(timeout=4.0) as http_client:
                response = await http_client.post(f"{INVENTORY_URL}/seed")
                response.raise_for_status()
        elif request.action == "clear_network_partition":
            if not request.target:
                raise HTTPException(status_code=400, detail="target_required")
            net_api.delete_namespaced_network_policy(f"{request.target}-deny-all", namespace)
        elif request.action == "reset_latency":
            if not request.target:
                raise HTTPException(status_code=400, detail="target_required")
            deployment = apps_api.read_namespaced_deployment(request.target, namespace)
            containers = patch_env(
                deployment.spec.template.spec.containers,
                request.container_name,
                "LATENCY_MS",
                "0",
            )
            if not containers:
                raise HTTPException(status_code=404, detail="container_not_found")
            patch = {"spec": {"template": {"spec": {"containers": containers}}}}
            apps_api.patch_namespaced_deployment(request.target, namespace, patch)
        else:
            raise HTTPException(status_code=400, detail="unknown_action")
        observe_event("recovery-engine", "recovery_executed")
        entry["status"] = "completed"
    except Exception as exc:
        entry["status"] = "failed"
        entry["error"] = str(exc)
        logger.exception("Recovery failed", extra=entry)
        add_timeline(entry)
        raise HTTPException(status_code=500, detail=str(exc))
    logger.info("Recovery executed", extra=entry)
    add_timeline(entry)
    return entry


@app.get("/timeline")
async def get_timeline() -> dict:
    return {"items": timeline}


@app.get("/workloads")
async def workloads() -> dict:
    apps_api, core_api, _ = load_k8s()
    items: list[dict[str, Any]] = []
    for namespace in target_namespaces(core_api):
        deployments = apps_api.list_namespaced_deployment(namespace).items
        pods = core_api.list_namespaced_pod(namespace).items
        pod_groups: dict[str, list[dict]] = {}
        for pod in pods:
            labels = pod.metadata.labels or {}
            app_label = labels.get("app")
            if app_label:
                pod_groups.setdefault(app_label, []).append(
                    {
                        "name": pod.metadata.name,
                        "phase": pod.status.phase,
                        "ip": pod.status.pod_ip,
                        "restarts": sum(c.restart_count for c in (pod.status.container_statuses or [])),
                    }
                )
        for deployment in deployments:
            app_label = (deployment.spec.selector.match_labels or {}).get("app", deployment.metadata.name)
            items.append(
                {
                    "namespace": namespace,
                    "name": deployment.metadata.name,
                    "kind": "deployment",
                    "ready": deployment.status.ready_replicas or 0,
                    "desired": deployment.spec.replicas or 0,
                    "available": deployment.status.available_replicas or 0,
                    "containers": [container.name for container in deployment.spec.template.spec.containers],
                    "pods": pod_groups.get(app_label, []),
                    "labels": deployment.metadata.labels or {},
                }
            )
    return {"items": items}
