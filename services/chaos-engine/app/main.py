from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException
from kubernetes import client, config
from pydantic import BaseModel
import yaml

from services.shared.audit import audit_event
from services.shared.history import record_history, recent_history
from services.shared.notifications import notification_worker, notify
from services.shared.observability import install_observability, observe_event, traced_get

app = FastAPI(title="chaos-engine")
logger = install_observability(app, "chaos-engine")
history: list[dict] = []
experiments: list[dict] = []
NAMESPACE = os.getenv("PLATFORM_NAMESPACE", "chaos-loop")
DEFAULT_TARGET_NAMESPACES = [
    item.strip() for item in os.getenv("TARGET_NAMESPACES", NAMESPACE).split(",") if item.strip()
]
SCHEDULE_PATH = Path(os.getenv("CHAOS_SCHEDULE_PATH", "/app/config/chaos-schedules.yaml"))
SCHEDULE_POLL_SECONDS = float(os.getenv("CHAOS_SCHEDULE_POLL_SECONDS", "5"))
TELEMETRY_URL = os.getenv("TELEMETRY_URL", "http://telemetry-bridge:8000")
schedule_state: dict[str, float] = {}


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
    ip_range: str | None = None


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
    record_history("chaos-history", "chaos-engine", event)
    return event


def record_experiment(event: dict) -> dict:
    experiments.append(event)
    del experiments[:-100]
    record_history("chaos-experiments", "chaos-engine", event)
    return event


def load_schedules() -> list[dict[str, Any]]:
    if not SCHEDULE_PATH.exists():
        return []
    try:
        payload = yaml.safe_load(SCHEDULE_PATH.read_text()) or {}
    except Exception as exc:
        logger.warning("Failed to load chaos schedules", extra={"path": str(SCHEDULE_PATH), "error": str(exc)})
        return []
    items = payload.get("experiments", payload)
    return [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []


async def evaluate_experiment(target: str) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await traced_get(client, f"{TELEMETRY_URL}/slo/status")
            response.raise_for_status()
            payload = response.json()
    except Exception as exc:
        return {"healed": False, "reason": str(exc)}
    item = next((entry for entry in payload.get("items", []) if entry.get("service") == target), None)
    if not item:
        return {"healed": True, "reason": "no_slo_for_target"}
    return {
        "healed": bool(item.get("healthy")),
        "reason": "slo_healthy" if item.get("healthy") else "slo_violated",
        "compliance": item.get("compliance"),
        "violations": item.get("violations", []),
    }


async def run_scenario_by_name(name: str, payload: dict[str, Any]) -> dict:
    request = ScenarioRequest(**payload)
    if name == "pod-crash":
        return await pod_crash(request)
    if name == "network-partition":
        return await network_partition(request)
    if name == "latency":
        return await latency(request)
    if name == "resource-pressure":
        return await resource_pressure(request)
    if name == "ddos-simulation":
        return await ddos_simulation(request)
    if name == "mitm-simulation":
        return await mitm_simulation(request)
    if name == "xss-probe":
        return await xss_probe(request)
    if name == "clickjacking-probe":
        return await clickjacking_probe(request)
    if name == "csrf-probe":
        return await csrf_probe(request)
    if name == "session-hijack-probe":
        return await session_hijack_probe(request)
    if name == "credential-stuffing-probe":
        return await credential_stuffing_probe(request)
    if name == "sqli-probe":
        return await sqli_probe(request)
    if name == "supply-chain-probe":
        return await supply_chain_probe(request)
    if name == "zero-day-probe":
        return await zero_day_probe(request)
    raise HTTPException(status_code=400, detail=f"unknown_scenario:{name}")


async def execute_experiment(plan: dict[str, Any]) -> dict[str, Any]:
    started = datetime.now(timezone.utc).isoformat()
    target = str(plan.get("target", ""))
    entry = {
        "ts": started,
        "name": plan.get("name", "unnamed"),
        "target": target,
        "status": "running",
        "steps": [],
    }
    record_experiment(entry)
    for step in plan.get("steps", []):
        if "wait_seconds" in step:
            await asyncio.sleep(float(step.get("wait_seconds", 0)))
            entry["steps"].append({"wait_seconds": float(step.get("wait_seconds", 0)), "status": "completed"})
            continue
        scenario = str(step.get("scenario"))
        payload = {**step.get("payload", {}), "target": target or step.get("target")}
        result = await run_scenario_by_name(scenario, payload)
        entry["steps"].append({"scenario": scenario, "payload": payload, "result": result, "status": "completed"})
    observe_window = float(plan.get("observe_seconds", 30))
    if observe_window > 0:
        await asyncio.sleep(observe_window)
    evaluation = await evaluate_experiment(target)
    entry["status"] = "completed"
    entry["completed_at"] = datetime.now(timezone.utc).isoformat()
    entry["evaluation"] = evaluation
    audit_event(
        "chaos-engine",
        "chaos-experiment",
        entry,
        severity="warning" if evaluation.get("healed", False) else "critical",
        status="completed",
        target=target,
    )
    await notify(
        "chaos-engine",
        "chaos_experiment_completed",
        "warning" if evaluation.get("healed", False) else "critical",
        f"Chaos experiment {entry['name']} {'self-healed' if evaluation.get('healed') else 'violated SLO'}",
        entry,
    )
    return entry


async def schedule_loop() -> None:
    while True:
        for plan in load_schedules():
            name = str(plan.get("name", "unnamed"))
            every = float(plan.get("interval_seconds", 0))
            if every <= 0:
                continue
            last_run = schedule_state.get(name, 0.0)
            if (datetime.now(timezone.utc).timestamp() - last_run) < every:
                continue
            schedule_state[name] = datetime.now(timezone.utc).timestamp()
            try:
                await execute_experiment(plan)
            except Exception as exc:
                logger.exception("Scheduled experiment failed", extra={"name": name, "error": str(exc)})
        await asyncio.sleep(SCHEDULE_POLL_SECONDS)


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


@app.post("/scenarios/ddos-simulation")
async def ddos_simulation(request: ScenarioRequest) -> dict:
    observe_event("chaos-engine", "ddos_simulation_injected")
    return record(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "scenario": "ddos-simulation",
            "target": request.target,
            "namespace": target_namespace(request),
            "ip_range": request.ip_range or "198.51.100.0/24",
        }
    )


@app.post("/scenarios/mitm-simulation")
async def mitm_simulation(request: ScenarioRequest) -> dict:
    observe_event("chaos-engine", "mitm_simulation_injected")
    return record(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "scenario": "mitm-simulation",
            "target": request.target,
            "namespace": target_namespace(request),
        }
    )


@app.post("/scenarios/xss-probe")
async def xss_probe(request: ScenarioRequest) -> dict:
    observe_event("chaos-engine", "xss_probe_injected")
    return record(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "scenario": "xss-probe",
            "target": request.target,
            "namespace": target_namespace(request),
        }
    )


@app.post("/scenarios/clickjacking-probe")
async def clickjacking_probe(request: ScenarioRequest) -> dict:
    observe_event("chaos-engine", "clickjacking_probe_injected")
    return record(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "scenario": "clickjacking-probe",
            "target": request.target,
            "namespace": target_namespace(request),
        }
    )


@app.post("/scenarios/csrf-probe")
async def csrf_probe(request: ScenarioRequest) -> dict:
    observe_event("chaos-engine", "csrf_probe_injected")
    return record(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "scenario": "csrf-probe",
            "target": request.target,
            "namespace": target_namespace(request),
        }
    )


@app.post("/scenarios/session-hijack-probe")
async def session_hijack_probe(request: ScenarioRequest) -> dict:
    observe_event("chaos-engine", "session_hijack_probe_injected")
    return record(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "scenario": "session-hijack-probe",
            "target": request.target,
            "namespace": target_namespace(request),
        }
    )


@app.post("/scenarios/credential-stuffing-probe")
async def credential_stuffing_probe(request: ScenarioRequest) -> dict:
    observe_event("chaos-engine", "credential_stuffing_probe_injected")
    return record(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "scenario": "credential-stuffing-probe",
            "target": request.target,
            "namespace": target_namespace(request),
        }
    )


@app.post("/scenarios/sqli-probe")
async def sqli_probe(request: ScenarioRequest) -> dict:
    observe_event("chaos-engine", "sqli_probe_injected")
    return record(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "scenario": "sqli-probe",
            "target": request.target,
            "namespace": target_namespace(request),
        }
    )


@app.post("/scenarios/supply-chain-probe")
async def supply_chain_probe(request: ScenarioRequest) -> dict:
    observe_event("chaos-engine", "supply_chain_probe_injected")
    return record(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "scenario": "supply-chain-probe",
            "target": request.target,
            "namespace": target_namespace(request),
        }
    )


@app.post("/scenarios/zero-day-probe")
async def zero_day_probe(request: ScenarioRequest) -> dict:
    observe_event("chaos-engine", "zero_day_probe_injected")
    return record(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "scenario": "zero-day-probe",
            "target": request.target,
            "namespace": target_namespace(request),
        }
    )


@app.get("/history")
async def get_history() -> dict:
    return {"items": recent_history("chaos-history", 100) or history}


@app.get("/experiments")
async def get_experiments() -> dict:
    return {"items": recent_history("chaos-experiments", 100) or experiments}


@app.post("/experiments/run")
async def run_experiment(payload: dict[str, Any]) -> dict:
    return await execute_experiment(payload)


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


@app.on_event("startup")
async def startup() -> None:
    asyncio.create_task(notification_worker())
    asyncio.create_task(schedule_loop())
