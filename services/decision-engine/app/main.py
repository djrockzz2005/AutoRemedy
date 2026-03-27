from __future__ import annotations

import asyncio
import os
import time
from collections import defaultdict
from typing import Any

import httpx
from fastapi import FastAPI

from services.shared.observability import install_observability

app = FastAPI(title="decision-engine")
logger = install_observability(app, "decision-engine")

DETECTOR_URL = os.getenv("DETECTOR_URL", "http://anomaly-detector:8000")
RECOVERY_URL = os.getenv("RECOVERY_URL", "http://recovery-engine:8000")
DECISION_INTERVAL = float(os.getenv("DECISION_INTERVAL_SECONDS", "2"))
COOLDOWN_SECONDS = float(os.getenv("COOLDOWN_SECONDS", "60"))
processed: set[str] = set()
decisions: list[dict] = []
last_recovery_at: dict[tuple[str, str], float] = {}


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
    return None


def plan_actions(event: dict) -> list[dict]:
    classification = event.get("classification")
    sample = event.get("sample", {})
    target = attributed_target(event)
    if classification == "pod_instability":
        return [{"action": "restart_deployment", "target": target or "order-service"}]
    if classification == "latency_spike":
        return [
            {"action": "scale_deployment", "target": target or "order-service", "replicas": 3},
            {"action": "reset_latency", "target": target or "api-gateway"},
        ]
    if classification == "availability_regression":
        return [
            {"action": "clear_network_partition", "target": target or "payment-service"},
            {"action": "restart_deployment", "target": target or "payment-service"},
        ]
    if classification == "application_error_burst" or sample.get("loki_errors", 0) > 4:
        if target == "recommendation-service":
            return [
                {
                    "action": "reroute_service",
                    "service_name": "recommendation-service",
                    "selector_value": "shadow",
                },
                {"action": "restore_cache"},
            ]
        return [
            {"action": "restart_deployment", "target": target or "api-gateway"},
        ]
    return [{"action": "restart_deployment", "target": "api-gateway"}]


def is_in_cooldown(classification: str, target: str) -> bool:
    last_seen = last_recovery_at.get((classification, target))
    if last_seen is None:
        return False
    return (time.time() - last_seen) < COOLDOWN_SECONDS


async def control_loop() -> None:
    while True:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{DETECTOR_URL}/events")
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
                    decisions.append(
                        {
                            "event": event,
                            "actions": planned,
                            "results": [],
                            "suppressed": True,
                            "reason": "cooldown",
                        }
                    )
                    del decisions[:-100]
                    processed.add(event["ts"])
                    continue
                decision_record = {"event": event, "actions": planned, "results": []}
                for action in planned:
                    payload = {**action, "reason": event["classification"]}
                    try:
                        action_response = await client.post(f"{RECOVERY_URL}/recover", json=payload)
                        decision_record["results"].append(action_response.json())
                    except Exception as exc:
                        decision_record["results"].append({"status": "failed", "error": str(exc), **payload})
                decisions.append(decision_record)
                del decisions[:-100]
                last_recovery_at[(event["classification"], target)] = time.time()
                processed.add(event["ts"])
                logger.info("Decision executed", extra={"event": event["classification"], "actions": planned})
        await asyncio.sleep(DECISION_INTERVAL)


@app.on_event("startup")
async def startup() -> None:
    asyncio.create_task(control_loop())


@app.get("/decisions")
async def get_decisions() -> dict:
    return {"items": decisions}
