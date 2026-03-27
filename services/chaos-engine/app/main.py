from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException
from kubernetes import client, config
from pydantic import BaseModel

from services.shared.observability import install_observability, observe_event

app = FastAPI(title="chaos-engine")
logger = install_observability(app, "chaos-engine")
history: list[dict] = []
NAMESPACE = os.getenv("PLATFORM_NAMESPACE", "chaos-loop")
DEFAULT_TARGET_NAMESPACES = [
    item.strip() for item in os.getenv("TARGET_NAMESPACES", NAMESPACE).split(",") if item.strip()
]


def load_k8s() -> tuple[client.AppsV1Api, client.CoreV1Api, client.NetworkingV1Api, client.BatchV1Api]:
    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()
    return client.AppsV1Api(), client.CoreV1Api(), client.NetworkingV1Api(), client.BatchV1Api()


class ScenarioRequest(BaseModel):
    target: str
    namespace: str | None = None
    kind: str = "deployment"
    pod_name: str | None = None
    container_name: str | None = None
    selector: str | None = None
    latency_ms: int | None = None


def target_namespace(request: ScenarioRequest) -> str:
    return request.namespace or DEFAULT_TARGET_NAMESPACES[0]


def target_namespaces(core_api: client.CoreV1Api) -> list[str]:
    if DEFAULT_TARGET_NAMESPACES == ["*"] or DEFAULT_TARGET_NAMESPACES == ["all"]:
        return [item.metadata.name for item in core_api.list_namespace().items]
    return DEFAULT_TARGET_NAMESPACES


def resolve_selector(request: ScenarioRequest) -> str:
    if request.selector:
        return request.selector
    if request.kind == "pod":
        return f"app={request.target}"
    return f"app={request.target}"


def patch_env(containers: list[client.V1Container], container_name: str | None, env_name: str, env_value: str) -> list[dict]:
    patches = []
    for container in containers:
        if container_name and container.name != container_name:
            continue
        env = [{"name": item.name, "value": item.value} for item in (container.env or []) if item.name != env_name]
        env.append({"name": env_name, "value": env_value})
        patches.append({"name": container.name, "env": env})
    return patches


def record(event: dict) -> dict:
    history.append(event)
    del history[:-100]
    return event


@app.post("/scenarios/pod-crash")
async def pod_crash(request: ScenarioRequest) -> dict:
    _, core_api, _, _ = load_k8s()
    namespace = target_namespace(request)
    pods = core_api.list_namespaced_pod(namespace, label_selector=resolve_selector(request)).items
    if request.pod_name:
        pods = [pod for pod in pods if pod.metadata and pod.metadata.name == request.pod_name]
    if not pods:
        raise HTTPException(status_code=404, detail="no_pod_found")
    core_api.delete_namespaced_pod(pods[0].metadata.name, namespace)
    observe_event("chaos-engine", "pod_crash_injected")
    return record(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "scenario": "pod-crash",
            "target": request.target,
            "namespace": namespace,
            "pod": pods[0].metadata.name,
        }
    )


@app.post("/scenarios/network-partition")
async def network_partition(request: ScenarioRequest) -> dict:
    _, _, net_api, _ = load_k8s()
    namespace = target_namespace(request)
    policy = client.V1NetworkPolicy(
        metadata=client.V1ObjectMeta(name=f"{request.target}-deny-all"),
        spec=client.V1NetworkPolicySpec(
            pod_selector=client.V1LabelSelector(match_labels={"app": request.target}),
            policy_types=["Ingress", "Egress"],
        ),
    )
    net_api.create_namespaced_network_policy(namespace, policy)
    observe_event("chaos-engine", "network_partition_injected")
    return record(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "scenario": "network-partition",
            "target": request.target,
            "namespace": namespace,
        }
    )


@app.post("/scenarios/latency")
async def latency(request: ScenarioRequest) -> dict:
    apps_api, _, _, _ = load_k8s()
    namespace = target_namespace(request)
    deployment = apps_api.read_namespaced_deployment(request.target, namespace)
    containers = patch_env(
        deployment.spec.template.spec.containers,
        request.container_name,
        "LATENCY_MS",
        str(request.latency_ms or 1500),
    )
    if not containers:
        raise HTTPException(status_code=404, detail="container_not_found")
    patch = {"spec": {"template": {"spec": {"containers": containers}}}}
    apps_api.patch_namespaced_deployment(request.target, namespace, patch)
    observe_event("chaos-engine", "latency_injected")
    return record(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "scenario": "latency",
            "target": request.target,
            "namespace": namespace,
            "container": request.container_name or containers[0]["name"],
            "latency_ms": request.latency_ms or 1500,
        }
    )


@app.post("/scenarios/resource-pressure")
async def resource_pressure(request: ScenarioRequest) -> dict:
    _, _, _, batch_api = load_k8s()
    namespace = target_namespace(request)
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
    batch_api.create_namespaced_job(namespace, job)
    observe_event("chaos-engine", "resource_pressure_injected")
    return record(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "scenario": "resource-pressure",
            "target": request.target,
            "namespace": namespace,
        }
    )


@app.get("/history")
async def get_history() -> dict:
    return {"items": history}


@app.get("/targets")
async def targets() -> dict:
    apps_api, core_api, _, _ = load_k8s()
    items: list[dict[str, Any]] = []
    for namespace in target_namespaces(core_api):
        deployments = apps_api.list_namespaced_deployment(namespace).items
        pods = core_api.list_namespaced_pod(namespace).items
        pod_index: dict[str, list[dict]] = {}
        for pod in pods:
            owner = next((ref.name for ref in (pod.metadata.owner_references or []) if ref.kind == "ReplicaSet"), None)
            key = owner or ""
            pod_index.setdefault(key, []).append(
                {
                    "name": pod.metadata.name,
                    "phase": pod.status.phase,
                    "ready": sum(1 for c in (pod.status.container_statuses or []) if c.ready),
                    "restarts": sum(c.restart_count for c in (pod.status.container_statuses or [])),
                }
            )
        for deployment in deployments:
            rs_prefix = f"{deployment.metadata.name}-"
            related_pods = [pod for key, group in pod_index.items() if key.startswith(rs_prefix) for pod in group]
            items.append(
                {
                    "kind": "deployment",
                    "namespace": namespace,
                    "name": deployment.metadata.name,
                    "ready": deployment.status.ready_replicas or 0,
                    "desired": deployment.spec.replicas or 0,
                    "available": deployment.status.available_replicas or 0,
                    "containers": [container.name for container in deployment.spec.template.spec.containers],
                    "pods": related_pods,
                }
            )
    return {"items": items}
