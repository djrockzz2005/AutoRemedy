from __future__ import annotations

import asyncio
import hashlib
import os
import random
import time
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI
import yaml

from services.shared.audit import audit_event
from services.shared.history import record_history, recent_history
from services.shared.notifications import notification_worker, notify
from services.shared.observability import install_observability, traced_get, traced_post

app = FastAPI(title="decision-engine")
logger = install_observability(app, "decision-engine")

DETECTOR_URL = os.getenv("DETECTOR_URL", "http://anomaly-detector:8000")
RECOVERY_URL = os.getenv("RECOVERY_URL", "http://recovery-engine:8000")
DECISION_INTERVAL = float(os.getenv("DECISION_INTERVAL_SECONDS", "2"))
COOLDOWN_SECONDS = float(os.getenv("COOLDOWN_SECONDS", "60"))
MAX_RETRIES_PER_TARGET = int(os.getenv("MAX_RETRIES_PER_TARGET", "3"))
CIRCUIT_BREAKER_THRESHOLD = int(os.getenv("CIRCUIT_BREAKER_THRESHOLD", "3"))
CIRCUIT_BREAKER_SECONDS = float(os.getenv("CIRCUIT_BREAKER_SECONDS", "300"))
PLAYBOOK_PATH = Path(os.getenv("PLAYBOOK_PATH", "/app/config/playbooks.yaml"))
FEEDBACK_WINDOW = int(os.getenv("FEEDBACK_WINDOW", "200"))
RL_EPSILON = float(os.getenv("RL_EPSILON", "0.15"))
RL_MIN_OBSERVATIONS = int(os.getenv("RL_MIN_OBSERVATIONS", "2"))
RL_SUCCESS_PRIOR = float(os.getenv("RL_SUCCESS_PRIOR", "1.0"))
RL_FAILURE_PRIOR = float(os.getenv("RL_FAILURE_PRIOR", "1.0"))
processed: set[str] = set()
decisions: list[dict] = []
last_recovery_at: dict[tuple[str, str], float] = {}
retry_counts: dict[tuple[str, str], int] = {}
failure_streaks: dict[tuple[str, str], int] = {}
circuit_open_until: dict[tuple[str, str], float] = {}
playbooks: dict[str, list[dict[str, Any]]] = {}


def top_service(
    per_service: dict[str, Any],
    metric: str,
    prefer_highest: bool = True,
) -> str | None:
    services = per_service.get("services", {}) if isinstance(per_service, dict) else {}
    if not services:
        return None
    ranking = sorted(
        services.items(),
        key=lambda item: item[1].get(metric, 0.0 if prefer_highest else 1.0),
        reverse=prefer_highest,
    )
    return ranking[0][0] if ranking else None


def attributed_target(event: dict) -> str | None:
    if event.get("target_service"):
        return str(event["target_service"])
    classification = event.get("classification")
    per_service = event.get("per_service", {})
    if classification == "pod_instability":
        return top_service(per_service, "restarts", True)
    if classification == "latency_spike":
        return top_service(per_service, "latency_p95", True)
    if classification == "availability_regression":
        error_target = top_service(per_service, "error_rate", True)
        availability_target = top_service(per_service, "availability", False)
        if error_target and availability_target:
            error_rate = per_service["services"].get(error_target, {}).get("error_rate", 0.0)
            availability = per_service["services"].get(availability_target, {}).get("availability", 1.0)
            return error_target if error_rate >= max(0.1, 1.0 - availability) else availability_target
        return error_target or availability_target
    if classification == "application_error_burst":
        return top_service(per_service, "loki_errors", True)
    if classification == "ddos_attack":
        return top_service(per_service, "requests_per_ip_per_second", True) or top_service(per_service, "connection_count", True)
    if classification == "mitm_attack":
        return top_service(per_service, "tls_handshake_failures", True) or top_service(per_service, "certificate_mismatch_count", True)
    if classification == "xss_attack":
        return top_service(per_service, "xss_attempt_count", True)
    if classification == "clickjacking_attack":
        return top_service(per_service, "clickjack_attempt_count", True)
    if classification == "csrf_attack":
        return top_service(per_service, "csrf_attempt_count", True)
    if classification == "session_hijacking_attack":
        return top_service(per_service, "session_hijack_attempt_count", True)
    if classification == "credential_stuffing_attack":
        return top_service(per_service, "credential_stuffing_attempt_count", True)
    if classification == "sqli_attack":
        return top_service(per_service, "sqli_attempt_count", True)
    if classification == "supply_chain_attack":
        return top_service(per_service, "supply_chain_risk_count", True)
    if classification == "zero_day_attack":
        return top_service(per_service, "zero_day_signal_count", True)
    return None


def default_target_for(classification: str | None) -> str:
    return {
        "pod_instability": "order-service",
        "latency_spike": "order-service",
        "availability_regression": "payment-service",
        "application_error_burst": "api-gateway",
        "ddos_attack": "api-gateway",
        "mitm_attack": "api-gateway",
        "xss_attack": "api-gateway",
        "clickjacking_attack": "dashboard",
        "csrf_attack": "dashboard",
        "session_hijacking_attack": "dashboard",
        "credential_stuffing_attack": "dashboard",
        "sqli_attack": "api-gateway",
        "supply_chain_attack": "api-gateway",
        "zero_day_attack": "api-gateway",
    }.get(classification or "", "api-gateway")


def load_playbooks() -> dict[str, list[dict[str, Any]]]:
    if not PLAYBOOK_PATH.exists():
        return {}
    try:
        payload = yaml.safe_load(PLAYBOOK_PATH.read_text()) or {}
    except Exception as exc:
        logger.warning("Playbook load failed", extra={"path": str(PLAYBOOK_PATH), "error": str(exc)})
        return {}
    items = payload.get("playbooks", payload)
    if not isinstance(items, dict):
        return {}
    loaded: dict[str, list[dict[str, Any]]] = {}
    for classification, actions in items.items():
        if isinstance(actions, list):
            loaded[str(classification)] = [action for action in actions if isinstance(action, dict)]
    return loaded


def render_playbook_value(value: Any, context: dict[str, Any]) -> Any:
    if isinstance(value, str):
        try:
            return value.format_map(context)
        except Exception:
            return value
    if isinstance(value, list):
        return [render_playbook_value(item, context) for item in value]
    if isinstance(value, dict):
        return {key: render_playbook_value(item, context) for key, item in value.items()}
    return value


def canonical_target(action: dict[str, Any], fallback_target: str) -> str:
    return str(action.get("target") or action.get("service_name") or fallback_target)


def action_signature(classification: str, action: dict[str, Any], fallback_target: str) -> str:
    target = canonical_target(action, fallback_target)
    parts = [
        str(classification or "unknown"),
        str(action.get("action", "unknown")),
        target,
    ]
    if "replicas" in action:
        parts.append(f"replicas={action.get('replicas')}")
    if "selector_value" in action:
        parts.append(f"selector={action.get('selector_value')}")
    return "|".join(parts)


def action_feedback_stats() -> dict[str, dict[str, float]]:
    items = recent_history("decision-log", FEEDBACK_WINDOW) or decisions
    stats: dict[str, dict[str, float]] = {}
    for item in items:
        if item.get("suppressed"):
            continue
        event = item.get("event", {})
        classification = str(event.get("classification", "unknown"))
        actions = [action for action in item.get("actions", []) if isinstance(action, dict)]
        results = item.get("results", [])
        target = next(
            (action.get("target") or action.get("service_name") for action in actions if action.get("target") or action.get("service_name")),
            default_target_for(classification),
        )
        for index, action in enumerate(actions):
            signature = action_signature(classification, action, str(target))
            bucket = stats.setdefault(signature, {"successes": 0.0, "failures": 0.0, "observations": 0.0})
            result = results[index] if index < len(results) and isinstance(results[index], dict) else {}
            succeeded = result.get("status") != "failed"
            bucket["observations"] += 1.0
            if succeeded:
                bucket["successes"] += 1.0
            else:
                bucket["failures"] += 1.0
    return stats


def action_score(classification: str, action: dict[str, Any], fallback_target: str, stats: dict[str, dict[str, float]]) -> float:
    bucket = stats.get(action_signature(classification, action, fallback_target), {})
    successes = float(bucket.get("successes", 0.0)) + RL_SUCCESS_PRIOR
    failures = float(bucket.get("failures", 0.0)) + RL_FAILURE_PRIOR
    return successes / max(successes + failures, 1.0)


def explore_actions(event: dict, planned: list[dict], classification: str, fallback_target: str, stats: dict[str, dict[str, float]]) -> list[dict]:
    if len(planned) < 2 or RL_EPSILON <= 0:
        return planned
    seed_material = str(event.get("ts") or event.get("classification") or time.time())
    seed = int(hashlib.sha256(seed_material.encode()).hexdigest()[:8], 16)
    if random.Random(seed).random() >= RL_EPSILON:
        return planned
    ranked = sorted(
        planned,
        key=lambda action: (
            float(stats.get(action_signature(classification, action, fallback_target), {}).get("observations", 0.0)),
            action_score(classification, action, fallback_target, stats),
        ),
    )
    return ranked if ranked else planned


def rank_actions_with_feedback(event: dict, planned: list[dict]) -> list[dict]:
    if len(planned) < 2:
        return planned
    classification = str(event.get("classification", "unknown"))
    fallback_target = next(
        (action.get("target") or action.get("service_name") for action in planned if action.get("target") or action.get("service_name")),
        default_target_for(classification),
    )
    stats = action_feedback_stats()
    ranked = sorted(
        planned,
        key=lambda action: (
            float(stats.get(action_signature(classification, action, str(fallback_target)), {}).get("observations", 0.0)) >= RL_MIN_OBSERVATIONS,
            action_score(classification, action, str(fallback_target), stats),
        ),
        reverse=True,
    )
    return explore_actions(event, ranked, classification, str(fallback_target), stats)


def plan_from_playbook(event: dict, target: str | None) -> list[dict]:
    actions = playbooks.get(str(event.get("classification")))
    if not actions:
        return []
    fallback = default_target_for(event.get("classification"))
    context = {
        "target": target or fallback,
        "classification": event.get("classification", ""),
        "fallback_target": fallback,
    }
    return [render_playbook_value(action, context) for action in actions]


def plan_actions(event: dict) -> list[dict]:
    classification = event.get("classification")
    sample = event.get("sample", {})
    target = attributed_target(event)
    configured = plan_from_playbook(event, target)
    if configured:
        return rank_actions_with_feedback(event, configured)
    planned: list[dict]
    if classification == "pod_instability":
        planned = [{"action": "restart_deployment", "target": target or default_target_for(classification)}]
    elif classification == "latency_spike":
        planned = [
            {"action": "scale_deployment", "target": target or default_target_for(classification), "replicas": 3},
            {"action": "reset_latency", "target": target or default_target_for(classification)},
        ]
    elif classification == "availability_regression":
        planned = [
            {"action": "clear_network_partition", "target": target or default_target_for(classification)},
            {"action": "restart_deployment", "target": target or default_target_for(classification)},
        ]
    elif classification == "application_error_burst" or sample.get("loki_errors", 0) > 4:
        if target == "recommendation-service":
            planned = [
                {
                    "action": "reroute_service",
                    "service_name": "recommendation-service",
                    "selector_value": "shadow",
                },
                {"action": "restore_cache"},
            ]
        else:
            planned = [
                {"action": "restart_deployment", "target": target or default_target_for(classification)},
            ]
    elif classification == "ddos_attack":
        planned = [
            {"action": "apply_rate_limit", "target": target or default_target_for(classification)},
            {"action": "scale_under_ddos", "target": target or default_target_for(classification), "replicas": 6},
        ]
    elif classification == "mitm_attack":
        planned = [
            {"action": "enforce_mtls", "target": target or default_target_for(classification)},
            {"action": "rotate_certificates", "target": target or default_target_for(classification)},
        ]
    elif classification == "xss_attack":
        planned = [
            {"action": "enable_waf_rules", "target": target or default_target_for(classification)},
        ]
    elif classification == "clickjacking_attack":
        planned = [
            {"action": "enforce_frame_policy", "target": target or default_target_for(classification)},
        ]
    elif classification == "csrf_attack":
        planned = [
            {"action": "lockdown_mutations", "target": target or default_target_for(classification)},
        ]
    elif classification == "session_hijacking_attack":
        planned = [
            {"action": "quarantine_sessions", "target": target or default_target_for(classification)},
        ]
    elif classification == "credential_stuffing_attack":
        planned = [
            {"action": "throttle_authentication", "target": target or default_target_for(classification)},
        ]
    elif classification == "sqli_attack":
        planned = [
            {"action": "enable_sql_guard", "target": target or default_target_for(classification)},
        ]
    elif classification == "supply_chain_attack":
        planned = [
            {"action": "isolate_third_party_egress", "target": target or default_target_for(classification)},
        ]
    elif classification == "zero_day_attack":
        planned = [
            {"action": "enable_emergency_patch_mode", "target": target or default_target_for(classification)},
        ]
    else:
        planned = [{"action": "restart_deployment", "target": default_target_for(classification)}]
    return rank_actions_with_feedback(event, planned)


def is_in_cooldown(classification: str, target: str) -> bool:
    last_seen = last_recovery_at.get((classification, target))
    if last_seen is None:
        return False
    return (time.time() - last_seen) < COOLDOWN_SECONDS


def circuit_is_open(classification: str, target: str) -> bool:
    until = circuit_open_until.get((classification, target), 0.0)
    return until > time.time()


def mark_outcome(classification: str, target: str, succeeded: bool) -> None:
    key = (classification, target)
    if succeeded:
        retry_counts[key] = 0
        failure_streaks[key] = 0
        circuit_open_until.pop(key, None)
        return
    retry_counts[key] = retry_counts.get(key, 0) + 1
    failure_streaks[key] = failure_streaks.get(key, 0) + 1
    if failure_streaks[key] >= CIRCUIT_BREAKER_THRESHOLD:
        circuit_open_until[key] = time.time() + CIRCUIT_BREAKER_SECONDS


async def record_suppression(event: dict, planned: list[dict], reason: str, target: str, severity: str = "warning") -> None:
    decision = {
        "event": event,
        "actions": planned,
        "results": [],
        "suppressed": True,
        "reason": reason,
    }
    decisions.append(decision)
    del decisions[:-100]
    record_history("decision-log", "decision-engine", decision)
    audit_event(
        "decision-engine",
        "decision-suppressed",
        decision,
        severity=severity,
        status=reason,
        target=target,
        classification=event.get("classification"),
    )
    await notify(
        "decision-engine",
        "decision_suppressed",
        severity,
        f"Suppressed {event.get('classification')} remediation for {target}: {reason}",
        decision,
    )


async def control_loop() -> None:
    while True:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await traced_get(client, f"{DETECTOR_URL}/events")
                response.raise_for_status()
                items = response.json()["items"]
        except Exception as exc:
            logger.warning("Decision fetch failed", extra={"error": str(exc)})
            await asyncio.sleep(DECISION_INTERVAL)
            continue

        async with httpx.AsyncClient(timeout=8.0) as client:
            for event in items:
                if event["ts"] in processed:
                    continue
                planned = plan_actions(event)
                target = next(
                    (action.get("target") or action.get("service_name") for action in planned if action.get("target") or action.get("service_name")),
                    "unknown",
                )
                if is_in_cooldown(event["classification"], target):
                    logger.info(
                        "Recovery suppressed by cooldown",
                        extra={
                            "classification": event["classification"],
                            "target": target,
                            "cooldown_seconds": COOLDOWN_SECONDS,
                        },
                    )
                    await record_suppression(event, planned, "cooldown", target)
                    processed.add(event["ts"])
                    continue
                if circuit_is_open(event["classification"], target):
                    logger.warning("Recovery suppressed by circuit breaker", extra={"classification": event["classification"], "target": target})
                    await record_suppression(event, planned, "circuit_open", target, severity="critical")
                    processed.add(event["ts"])
                    continue
                if retry_counts.get((event["classification"], target), 0) >= MAX_RETRIES_PER_TARGET:
                    logger.warning("Recovery suppressed by retry limit", extra={"classification": event["classification"], "target": target})
                    await record_suppression(event, planned, "retry_limit", target, severity="critical")
                    processed.add(event["ts"])
                    continue
                decision_record = {"event": event, "actions": planned, "results": []}
                for action in planned:
                    payload = {**action, "reason": event["classification"]}
                    try:
                        action_response = await traced_post(client, f"{RECOVERY_URL}/recover", json=payload)
                        action_response.raise_for_status()
                        decision_record["results"].append(action_response.json())
                    except Exception as exc:
                        decision_record["results"].append({"status": "failed", "error": str(exc), **payload})
                decisions.append(decision_record)
                del decisions[:-100]
                record_history("decision-log", "decision-engine", decision_record)
                succeeded = all(item.get("status") != "failed" for item in decision_record["results"])
                mark_outcome(event["classification"], target, succeeded)
                if succeeded:
                    last_recovery_at[(event["classification"], target)] = time.time()
                processed.add(event["ts"])
                audit_event(
                    "decision-engine",
                    "decision-executed",
                    decision_record,
                    severity="warning" if succeeded else "critical",
                    status="completed" if succeeded else "failed",
                    target=target,
                    classification=event.get("classification"),
                )
                await notify(
                    "decision-engine",
                    "decision_executed",
                    "warning" if succeeded else "critical",
                    f"{'Executed' if succeeded else 'Failed'} remediation for {event.get('classification')} on {target}",
                    decision_record,
                )
                logger.info("Decision executed", extra={"event": event["classification"], "actions": planned})
        await asyncio.sleep(DECISION_INTERVAL)


@app.on_event("startup")
async def startup() -> None:
    global playbooks
    playbooks = load_playbooks()
    asyncio.create_task(notification_worker())
    asyncio.create_task(control_loop())


@app.get("/decisions")
async def get_decisions() -> dict:
    return {"items": recent_history("decision-log", 100) or decisions}


@app.get("/feedback")
async def feedback() -> dict:
    items = recent_history("decision-log", 200) or decisions
    total = len(items)
    successful = 0
    failed = 0
    suppressed = 0
    latencies = []
    by_classification: dict[str, dict[str, Any]] = {}
    action_preferences: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        event = item.get("event", {})
        classification = event.get("classification", "unknown")
        bucket = by_classification.setdefault(classification, {"total": 0, "successful": 0, "failed": 0, "suppressed": 0})
        bucket["total"] += 1
        if item.get("suppressed"):
            suppressed += 1
            bucket["suppressed"] += 1
            continue
        results = item.get("results", [])
        succeeded = bool(results) and all(result.get("status") != "failed" for result in results)
        if succeeded:
            successful += 1
            bucket["successful"] += 1
            try:
                executed_at = last_recovery_at.get((classification, next((action.get("target") or action.get("service_name") for action in item.get("actions", []) if action.get("target") or action.get("service_name")), "unknown")))
                if executed_at and event.get("ts"):
                    latencies.append(max(0.0, executed_at - time.mktime(time.strptime(event["ts"][:19], "%Y-%m-%dT%H:%M:%S"))))
            except Exception:
                pass
        else:
            failed += 1
            bucket["failed"] += 1
    stats = action_feedback_stats()
    grouped_action_preferences: dict[str, list[dict[str, Any]]] = {}
    for signature, bucket in stats.items():
        classification, action_name, target, *details = signature.split("|")
        grouped_action_preferences.setdefault(classification, []).append(
            {
                "action": action_name,
                "target": target,
                "success_rate": round(
                    (float(bucket.get("successes", 0.0)) + RL_SUCCESS_PRIOR)
                    / max(float(bucket.get("observations", 0.0)) + RL_SUCCESS_PRIOR + RL_FAILURE_PRIOR, 1.0),
                    4,
                ),
                "observations": int(bucket.get("observations", 0.0)),
                "details": details,
            }
        )
    for classification, action_items in grouped_action_preferences.items():
        action_preferences[classification] = sorted(
            action_items,
            key=lambda item: (item["success_rate"], item["observations"]),
            reverse=True,
        )
    return {
        "total": total,
        "successful": successful,
        "failed": failed,
        "suppressed": suppressed,
        "success_rate": round(successful / max(total - suppressed, 1), 4),
        "avg_detection_to_action_seconds": round(sum(latencies) / len(latencies), 3) if latencies else 0.0,
        "by_classification": by_classification,
        "action_preferences": action_preferences,
    }
