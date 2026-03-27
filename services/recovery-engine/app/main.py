from __future__ import annotations

import os
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, HTTPException
from kubernetes import client, config
from pydantic import BaseModel

from services.shared.observability import install_observability, observe_event

app = FastAPI(title="recovery-engine")
logger = install_observability(app, "recovery-engine")
timeline: list[dict] = []
NAMESPACE = os.getenv("PLATFORM_NAMESPACE", "chaos-loop")
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
    replicas: int | None = None
    service_name: str | None = None
    selector_value: str | None = None
    reason: str | None = None


def add_timeline(entry: dict) -> None:
    timeline.append(entry)
    del timeline[:-200]


@app.post("/recover")
async def recover(request: RecoveryRequest) -> dict:
    apps_api, _, net_api = load_k8s()
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "action": request.action,
        "target": request.target,
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
            apps_api.patch_namespaced_deployment(request.target, NAMESPACE, patch)
        elif request.action == "scale_deployment":
            if request.replicas is None:
                raise HTTPException(status_code=400, detail="replicas_required")
            patch = {"spec": {"replicas": request.replicas}}
            apps_api.patch_namespaced_deployment_scale(request.target, NAMESPACE, patch)
        elif request.action == "reroute_service":
            if not request.service_name or not request.selector_value:
                raise HTTPException(status_code=400, detail="service_name_and_selector_value_required")
            patch = {"spec": {"selector": {"app": request.service_name, "lane": request.selector_value}}}
            client.CoreV1Api().patch_namespaced_service(request.service_name, NAMESPACE, patch)
        elif request.action == "restore_cache":
            async with httpx.AsyncClient(timeout=4.0) as http_client:
                response = await http_client.post(f"{INVENTORY_URL}/seed")
                response.raise_for_status()
        elif request.action == "clear_network_partition":
            if not request.target:
                raise HTTPException(status_code=400, detail="target_required")
            net_api.delete_namespaced_network_policy(f"{request.target}-deny-all", NAMESPACE)
        elif request.action == "reset_latency":
            if not request.target:
                raise HTTPException(status_code=400, detail="target_required")
            patch = {
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "name": request.target,
                                    "env": [{"name": "LATENCY_MS", "value": "0"}],
                                }
                            ]
                        }
                    }
                }
            }
            apps_api.patch_namespaced_deployment(request.target, NAMESPACE, patch)
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

