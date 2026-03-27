from __future__ import annotations

import os
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from kubernetes import client, config
from pydantic import BaseModel

from services.shared.observability import install_observability, observe_event

app = FastAPI(title="chaos-engine")
logger = install_observability(app, "chaos-engine")
history: list[dict] = []
NAMESPACE = os.getenv("PLATFORM_NAMESPACE", "chaos-loop")


def load_k8s() -> tuple[client.AppsV1Api, client.CoreV1Api, client.NetworkingV1Api, client.BatchV1Api]:
    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()
    return client.AppsV1Api(), client.CoreV1Api(), client.NetworkingV1Api(), client.BatchV1Api()


class ScenarioRequest(BaseModel):
    target: str
    latency_ms: int | None = None


def record(event: dict) -> dict:
    history.append(event)
    del history[:-100]
    return event


@app.post("/scenarios/pod-crash")
async def pod_crash(request: ScenarioRequest) -> dict:
    _, core_api, _, _ = load_k8s()
    pods = core_api.list_namespaced_pod(NAMESPACE, label_selector=f"app={request.target}").items
    if not pods:
        raise HTTPException(status_code=404, detail="no_pod_found")
    core_api.delete_namespaced_pod(pods[0].metadata.name, NAMESPACE)
    observe_event("chaos-engine", "pod_crash_injected")
    return record({"ts": datetime.now(timezone.utc).isoformat(), "scenario": "pod-crash", "target": request.target})


@app.post("/scenarios/network-partition")
async def network_partition(request: ScenarioRequest) -> dict:
    _, _, net_api, _ = load_k8s()
    policy = client.V1NetworkPolicy(
        metadata=client.V1ObjectMeta(name=f"{request.target}-deny-all"),
        spec=client.V1NetworkPolicySpec(
            pod_selector=client.V1LabelSelector(match_labels={"app": request.target}),
            policy_types=["Ingress", "Egress"],
        ),
    )
    net_api.create_namespaced_network_policy(NAMESPACE, policy)
    observe_event("chaos-engine", "network_partition_injected")
    return record(
        {"ts": datetime.now(timezone.utc).isoformat(), "scenario": "network-partition", "target": request.target}
    )


@app.post("/scenarios/latency")
async def latency(request: ScenarioRequest) -> dict:
    apps_api, _, _, _ = load_k8s()
    patch = {
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": request.target,
                            "env": [{"name": "LATENCY_MS", "value": str(request.latency_ms or 1500)}],
                        }
                    ]
                }
            }
        }
    }
    apps_api.patch_namespaced_deployment(request.target, NAMESPACE, patch)
    observe_event("chaos-engine", "latency_injected")
    return record(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "scenario": "latency",
            "target": request.target,
            "latency_ms": request.latency_ms or 1500,
        }
    )


@app.post("/scenarios/resource-pressure")
async def resource_pressure(request: ScenarioRequest) -> dict:
    _, _, _, batch_api = load_k8s()
    job = client.V1Job(
        metadata=client.V1ObjectMeta(name=f"cpu-stress-{int(datetime.now().timestamp())}"),
        spec=client.V1JobSpec(
            ttl_seconds_after_finished=60,
            template=client.V1PodTemplateSpec(
                metadata=client.V1ObjectMeta(labels={"app": "cpu-stress"}),
                spec=client.V1PodSpec(
                    restart_policy="Never",
                    containers=[
                        client.V1Container(
                            name="stress",
                            image="alpine:3.20",
                            command=["/bin/sh", "-c", "dd if=/dev/zero of=/dev/null & dd if=/dev/zero of=/dev/null & sleep 45"],
                            resources=client.V1ResourceRequirements(
                                requests={"cpu": "500m", "memory": "128Mi"},
                                limits={"cpu": "1000m", "memory": "256Mi"},
                            ),
                        )
                    ],
                ),
            ),
        ),
    )
    batch_api.create_namespaced_job(NAMESPACE, job)
    observe_event("chaos-engine", "resource_pressure_injected")
    return record(
        {"ts": datetime.now(timezone.utc).isoformat(), "scenario": "resource-pressure", "target": request.target}
    )


@app.get("/history")
async def get_history() -> dict:
    return {"items": history}

