from __future__ import annotations

import os
import asyncio
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException
from kubernetes import client, config
from pydantic import BaseModel

from services.shared.audit import audit_event
from services.shared.history import record_history, recent_history
from services.shared.notifications import notification_worker, notify
from services.shared.observability import install_observability, observe_event, traced_post
from services.shared.security import set_control

app = FastAPI(title="recovery-engine")
logger = install_observability(app, "recovery-engine")
timeline: list[dict] = []
NAMESPACE = os.getenv("PLATFORM_NAMESPACE", "chaos-loop")
DEFAULT_TARGET_NAMESPACES = [
    item.strip() for item in os.getenv("TARGET_NAMESPACES", NAMESPACE).split(",") if item.strip()
]
INVENTORY_URL = os.getenv("INVENTORY_URL", "http://inventory-service:8000")
TELEMETRY_URL = os.getenv("TELEMETRY_URL", "http://telemetry-bridge:8000")
AUTO_RELAX_SECONDS = int(os.getenv("SECURITY_POSTURE_COOLDOWN_SECONDS", "90"))
active_mitigations: list[dict[str, Any]] = []


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
    ip_ranges: list[str] | None = None


def add_timeline(entry: dict) -> None:
    timeline.append(entry)
    del timeline[:-200]
    record_history("recovery-timeline", "recovery-engine", entry)


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


def remember_mitigation(entry: dict[str, Any]) -> None:
    active_mitigations.append(entry)
    del active_mitigations[:-100]


def find_mitigation(action: str, target: str | None, namespace: str) -> dict[str, Any] | None:
    for item in reversed(active_mitigations):
        if item.get("action") == action and item.get("target") == target and item.get("namespace") == namespace and item.get("active", True):
            return item
    return None


async def current_security_snapshot() -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=4.0) as client_http:
            response = await client_http.get(f"{TELEMETRY_URL}/features/latest")
            response.raise_for_status()
            return response.json()
    except Exception:
        return {}


def security_signal_cleared(reason: str, sample: dict[str, Any], target: str | None) -> bool:
    service_sample = ((sample.get("per_service") or {}).get(target or "", {}) if isinstance(sample.get("per_service"), dict) else {}) or sample
    if reason == "ddos_attack":
        return service_sample.get("requests_per_ip_per_second", 0.0) < 3 and service_sample.get("syn_flood_score", 0.0) < 0.1
    if reason == "mitm_attack":
        return (
            service_sample.get("tls_handshake_failures", 0.0) <= 0.0
            and service_sample.get("certificate_mismatch_count", 0.0) <= 0.0
            and service_sample.get("unexpected_certificate_fingerprints", 0.0) <= 0.0
        )
    if reason == "xss_attack":
        return service_sample.get("xss_attempt_count", 0.0) <= 0.0
    if reason == "csrf_attack":
        return service_sample.get("csrf_attempt_count", 0.0) <= 0.0
    return False


async def relax_security_posture_loop() -> None:
    while True:
        snapshot = await current_security_snapshot()
        now = datetime.now(timezone.utc).timestamp()
        for mitigation in list(active_mitigations):
            if not mitigation.get("active", True):
                continue
            if (now - mitigation.get("activated_at", now)) < AUTO_RELAX_SECONDS:
                continue
            if not security_signal_cleared(mitigation.get("reason", ""), snapshot, mitigation.get("target")):
                continue
            request = RecoveryRequest(
                action=mitigation["rollback_action"],
                target=mitigation.get("target"),
                namespace=mitigation.get("namespace"),
                replicas=mitigation.get("baseline_replicas"),
                reason=f"{mitigation.get('reason', 'security_event')}_recovered",
            )
            try:
                await recover(request)
                mitigation["active"] = False
            except Exception:
                logger.warning("Automatic posture relaxation failed", extra=mitigation)
        await asyncio.sleep(5)


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
                response = await traced_post(http_client, f"{INVENTORY_URL}/seed")
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
        elif request.action == "apply_rate_limit":
            if not request.target:
                raise HTTPException(status_code=400, detail="target_required")
            ip_ranges = request.ip_ranges or [os.getenv("DDOS_BLOCK_CIDR", "0.0.0.0/0")]
            ingress_rules = []
            for cidr in ip_ranges:
                ingress_rules.append(client.V1NetworkPolicyIngressRule(_from=[client.V1IPBlock(cidr=cidr, except_=["10.0.0.0/8"])]))
            policy = client.V1NetworkPolicy(
                metadata=client.V1ObjectMeta(name=f"{request.target}-ddos-guard"),
                spec=client.V1NetworkPolicySpec(
                    pod_selector=client.V1LabelSelector(match_labels={"app": request.target}),
                    ingress=ingress_rules,
                    policy_types=["Ingress"],
                ),
            )
            try:
                net_api.replace_namespaced_network_policy(f"{request.target}-ddos-guard", namespace, policy)
            except Exception:
                net_api.create_namespaced_network_policy(namespace, policy)
            set_control(request.target, "rate_limit", True, metadata={"ip_ranges": ip_ranges})
            remember_mitigation(
                {
                    "action": request.action,
                    "rollback_action": "remove_rate_limit",
                    "target": request.target,
                    "namespace": namespace,
                    "reason": request.reason,
                    "activated_at": datetime.now(timezone.utc).timestamp(),
                    "active": True,
                }
            )
        elif request.action == "remove_rate_limit":
            if not request.target:
                raise HTTPException(status_code=400, detail="target_required")
            net_api.delete_namespaced_network_policy(f"{request.target}-ddos-guard", namespace)
            set_control(request.target, "rate_limit", False)
        elif request.action == "scale_under_ddos":
            if not request.target:
                raise HTTPException(status_code=400, detail="target_required")
            deployment = apps_api.read_namespaced_deployment(request.target, namespace)
            baseline = deployment.spec.replicas or 1
            patch = {
                "metadata": {"annotations": {"autoremedy.io/hpa-burst-mode": "enabled"}},
                "spec": {"replicas": request.replicas or max(4, baseline * 2)},
            }
            apps_api.patch_namespaced_deployment(request.target, namespace, patch)
            set_control(request.target, "ddos_burst_mode", True)
            remember_mitigation(
                {
                    "action": request.action,
                    "rollback_action": "scale_deployment",
                    "target": request.target,
                    "namespace": namespace,
                    "reason": request.reason,
                    "activated_at": datetime.now(timezone.utc).timestamp(),
                    "baseline_replicas": baseline,
                    "active": True,
                }
            )
        elif request.action == "enforce_mtls":
            if not request.target:
                raise HTTPException(status_code=400, detail="target_required")
            policy = client.V1NetworkPolicy(
                metadata=client.V1ObjectMeta(name=f"{request.target}-strict-mtls"),
                spec=client.V1NetworkPolicySpec(
                    pod_selector=client.V1LabelSelector(match_labels={"app": request.target}),
                    ingress=[
                        client.V1NetworkPolicyIngressRule(
                            _from=[client.V1NetworkPolicyPeer(namespace_selector=client.V1LabelSelector(match_labels={"kubernetes.io/metadata.name": namespace}))]
                        )
                    ],
                    policy_types=["Ingress"],
                ),
            )
            try:
                net_api.replace_namespaced_network_policy(f"{request.target}-strict-mtls", namespace, policy)
            except Exception:
                net_api.create_namespaced_network_policy(namespace, policy)
            set_control(request.target, "strict_mtls", True)
            remember_mitigation(
                {
                    "action": request.action,
                    "rollback_action": "relax_mtls",
                    "target": request.target,
                    "namespace": namespace,
                    "reason": request.reason,
                    "activated_at": datetime.now(timezone.utc).timestamp(),
                    "active": True,
                }
            )
        elif request.action == "relax_mtls":
            if not request.target:
                raise HTTPException(status_code=400, detail="target_required")
            net_api.delete_namespaced_network_policy(f"{request.target}-strict-mtls", namespace)
            set_control(request.target, "strict_mtls", False)
        elif request.action == "rotate_certificates":
            if not request.target:
                raise HTTPException(status_code=400, detail="target_required")
            patch = {
                "spec": {
                    "template": {
                        "metadata": {
                            "annotations": {"autoremedy.io/cert-rotated-at": datetime.now(timezone.utc).isoformat()}
                        }
                    }
                }
            }
            apps_api.patch_namespaced_deployment(request.target, namespace, patch)
        elif request.action == "enable_waf_rules":
            if not request.target:
                raise HTTPException(status_code=400, detail="target_required")
            deployment = apps_api.read_namespaced_deployment(request.target, namespace)
            containers = patch_env(deployment.spec.template.spec.containers, request.container_name, "XSS_PROTECTION_MODE", "strict")
            patch = {"spec": {"template": {"spec": {"containers": containers}}}}
            apps_api.patch_namespaced_deployment(request.target, namespace, patch)
            set_control(request.target, "waf_strict", True)
            remember_mitigation(
                {
                    "action": request.action,
                    "rollback_action": "disable_waf_rules",
                    "target": request.target,
                    "namespace": namespace,
                    "reason": request.reason,
                    "activated_at": datetime.now(timezone.utc).timestamp(),
                    "active": True,
                }
            )
        elif request.action == "disable_waf_rules":
            if not request.target:
                raise HTTPException(status_code=400, detail="target_required")
            deployment = apps_api.read_namespaced_deployment(request.target, namespace)
            containers = patch_env(deployment.spec.template.spec.containers, request.container_name, "XSS_PROTECTION_MODE", "normal")
            patch = {"spec": {"template": {"spec": {"containers": containers}}}}
            apps_api.patch_namespaced_deployment(request.target, namespace, patch)
            set_control(request.target, "waf_strict", False)
        elif request.action == "enforce_frame_policy":
            if not request.target:
                raise HTTPException(status_code=400, detail="target_required")
            patch = {
                "spec": {
                    "template": {
                        "metadata": {
                            "annotations": {
                                "nginx.ingress.kubernetes.io/configuration-snippet": "add_header X-Frame-Options DENY always; add_header Content-Security-Policy \"frame-ancestors 'none'\" always;"
                            }
                        }
                    }
                }
            }
            apps_api.patch_namespaced_deployment(request.target, namespace, patch)
        elif request.action == "lockdown_mutations":
            if not request.target:
                raise HTTPException(status_code=400, detail="target_required")
            deployment = apps_api.read_namespaced_deployment(request.target, namespace)
            containers = patch_env(deployment.spec.template.spec.containers, request.container_name, "LOCKDOWN_MUTATIONS", "true")
            patch = {"spec": {"template": {"spec": {"containers": containers}}}}
            apps_api.patch_namespaced_deployment(request.target, namespace, patch)
            set_control(request.target, "lockdown_mutations", True)
            remember_mitigation(
                {
                    "action": request.action,
                    "rollback_action": "unlock_mutations",
                    "target": request.target,
                    "namespace": namespace,
                    "reason": request.reason,
                    "activated_at": datetime.now(timezone.utc).timestamp(),
                    "active": True,
                }
            )
        elif request.action == "unlock_mutations":
            if not request.target:
                raise HTTPException(status_code=400, detail="target_required")
            deployment = apps_api.read_namespaced_deployment(request.target, namespace)
            containers = patch_env(deployment.spec.template.spec.containers, request.container_name, "LOCKDOWN_MUTATIONS", "false")
            patch = {"spec": {"template": {"spec": {"containers": containers}}}}
            apps_api.patch_namespaced_deployment(request.target, namespace, patch)
            set_control(request.target, "lockdown_mutations", False)
        elif request.action == "quarantine_sessions":
            if not request.target:
                raise HTTPException(status_code=400, detail="target_required")
            set_control(request.target, "quarantine_sessions", True)
        elif request.action == "throttle_authentication":
            if not request.target:
                raise HTTPException(status_code=400, detail="target_required")
            deployment = apps_api.read_namespaced_deployment(request.target, namespace)
            containers = patch_env(deployment.spec.template.spec.containers, request.container_name, "AUTH_RATE_LIMIT_MODE", "strict")
            patch = {"spec": {"template": {"spec": {"containers": containers}}}}
            apps_api.patch_namespaced_deployment(request.target, namespace, patch)
            set_control(request.target, "auth_rate_limit", True)
        elif request.action == "enable_sql_guard":
            if not request.target:
                raise HTTPException(status_code=400, detail="target_required")
            deployment = apps_api.read_namespaced_deployment(request.target, namespace)
            containers = patch_env(deployment.spec.template.spec.containers, request.container_name, "SQL_GUARD_MODE", "strict")
            patch = {"spec": {"template": {"spec": {"containers": containers}}}}
            apps_api.patch_namespaced_deployment(request.target, namespace, patch)
            set_control(request.target, "sql_guard", True)
        elif request.action == "isolate_third_party_egress":
            if not request.target:
                raise HTTPException(status_code=400, detail="target_required")
            policy = client.V1NetworkPolicy(
                metadata=client.V1ObjectMeta(name=f"{request.target}-egress-lockdown"),
                spec=client.V1NetworkPolicySpec(
                    pod_selector=client.V1LabelSelector(match_labels={"app": request.target}),
                    policy_types=["Egress"],
                    egress=[],
                ),
            )
            try:
                net_api.replace_namespaced_network_policy(f"{request.target}-egress-lockdown", namespace, policy)
            except Exception:
                net_api.create_namespaced_network_policy(namespace, policy)
            set_control(request.target, "egress_lockdown", True)
        elif request.action == "enable_emergency_patch_mode":
            if not request.target:
                raise HTTPException(status_code=400, detail="target_required")
            deployment = apps_api.read_namespaced_deployment(request.target, namespace)
            containers = patch_env(deployment.spec.template.spec.containers, request.container_name, "EMERGENCY_PATCH_MODE", "true")
            patch = {"spec": {"template": {"spec": {"containers": containers}}}}
            apps_api.patch_namespaced_deployment(request.target, namespace, patch)
            set_control(request.target, "emergency_patch_mode", True)
        else:
            raise HTTPException(status_code=400, detail="unknown_action")
        observe_event("recovery-engine", "recovery_executed")
        entry["status"] = "completed"
        audit_event(
            "recovery-engine",
            "recovery-action",
            entry,
            severity="warning",
            status="completed",
            target=request.target,
            classification=request.reason,
        )
        await notify(
            "recovery-engine",
            "recovery_executed",
            "warning",
            f"{request.action} executed for {request.target or request.service_name or 'cluster'}",
            entry,
        )
    except Exception as exc:
        entry["status"] = "failed"
        entry["error"] = str(exc)
        logger.exception("Recovery failed", extra=entry)
        audit_event(
            "recovery-engine",
            "recovery-action",
            entry,
            severity="critical",
            status="failed",
            target=request.target,
            classification=request.reason,
        )
        await notify(
            "recovery-engine",
            "recovery_failed",
            "critical",
            f"{request.action} failed for {request.target or request.service_name or 'cluster'}",
            entry,
        )
        add_timeline(entry)
        raise HTTPException(status_code=500, detail=str(exc))
    logger.info("Recovery executed", extra=entry)
    add_timeline(entry)
    return entry


@app.get("/timeline")
async def get_timeline() -> dict:
    return {"items": recent_history("recovery-timeline", 200) or timeline}


@app.on_event("startup")
async def startup() -> None:
    asyncio.create_task(notification_worker())
    asyncio.create_task(relax_security_posture_loop())


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
