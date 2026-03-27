from __future__ import annotations

import asyncio
import os

import httpx
from fastapi import FastAPI

from services.shared.observability import install_observability

app = FastAPI(title="decision-engine")
logger = install_observability(app, "decision-engine")

DETECTOR_URL = os.getenv("DETECTOR_URL", "http://anomaly-detector:8000")
RECOVERY_URL = os.getenv("RECOVERY_URL", "http://recovery-engine:8000")
DECISION_INTERVAL = float(os.getenv("DECISION_INTERVAL_SECONDS", "2"))
processed: set[str] = set()
decisions: list[dict] = []


def plan_actions(event: dict) -> list[dict]:
    classification = event.get("classification")
    sample = event.get("sample", {})
    if classification == "pod_instability":
        return [{"action": "restart_deployment", "target": "order-service"}]
    if classification == "latency_spike":
        return [
            {"action": "scale_deployment", "target": "order-service", "replicas": 3},
            {"action": "reset_latency", "target": "api-gateway"},
        ]
    if classification == "availability_regression":
        return [
            {"action": "clear_network_partition", "target": "payment-service"},
            {"action": "restart_deployment", "target": "payment-service"},
        ]
    if sample.get("loki_errors", 0) > 4:
        return [
            {
                "action": "reroute_service",
                "service_name": "recommendation-service",
                "selector_value": "shadow",
            },
            {"action": "restore_cache"},
        ]
    return [{"action": "restart_deployment", "target": "api-gateway"}]


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
                processed.add(event["ts"])
                logger.info("Decision executed", extra={"event": event["classification"], "actions": planned})
        await asyncio.sleep(DECISION_INTERVAL)


@app.on_event("startup")
async def startup() -> None:
    asyncio.create_task(control_loop())


@app.get("/decisions")
async def get_decisions() -> dict:
    return {"items": decisions}
