from __future__ import annotations

import asyncio
import os
from collections import deque
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI

from services.shared.observability import install_observability

app = FastAPI(title="telemetry-bridge")
logger = install_observability(app, "telemetry-bridge")

PROM_URL = os.getenv("PROMETHEUS_URL", "http://prometheus:9090")
LOKI_URL = os.getenv("LOKI_URL", "http://loki:3100")
WINDOW = int(os.getenv("FEATURE_WINDOW", "120"))
history: deque[dict] = deque(maxlen=WINDOW)

QUERIES = {
    "request_rate": 'sum(rate(platform_http_requests_total{status!~"5.."}[1m]))',
    "error_rate": 'sum(rate(platform_http_requests_total{status=~"5.."}[1m]))',
    "latency_p95": 'histogram_quantile(0.95, sum(rate(platform_http_request_duration_seconds_bucket[5m])) by (le))',
    "restarts": 'sum(kube_pod_container_status_restarts_total{namespace="chaos-loop"})',
    "cpu": 'sum(rate(container_cpu_usage_seconds_total{namespace="chaos-loop",container!=""}[1m]))',
    "memory": 'sum(container_memory_working_set_bytes{namespace="chaos-loop",container!=""})',
}


async def prom_query(client: httpx.AsyncClient, query: str) -> float:
    response = await client.get(f"{PROM_URL}/api/v1/query", params={"query": query})
    response.raise_for_status()
    payload = response.json()
    result = payload.get("data", {}).get("result", [])
    if not result:
        return 0.0
    return float(result[0]["value"][1])


async def loki_error_count(client: httpx.AsyncClient) -> float:
    now_ns = int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)
    params = {
        "query": 'sum(count_over_time({service=~".+"} |= "error" [1m]))',
        "start": str(now_ns - 60_000_000_000),
        "end": str(now_ns),
    }
    response = await client.get(f"{LOKI_URL}/loki/api/v1/query", params=params)
    response.raise_for_status()
    result = response.json().get("data", {}).get("result", [])
    if not result:
        return 0.0
    return float(result[0]["value"][1])


async def collect_features() -> None:
    while True:
        sample = {"ts": datetime.now(timezone.utc).isoformat()}
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                for key, query in QUERIES.items():
                    sample[key] = await prom_query(client, query)
                sample["loki_errors"] = await loki_error_count(client)
                total = sample["request_rate"] + sample["error_rate"]
                sample["availability"] = 1.0 if total == 0 else sample["request_rate"] / total
        except Exception as exc:
            sample["collector_error"] = str(exc)
            logger.warning("Telemetry collection degraded", extra={"error": str(exc)})
            for key in QUERIES:
                sample.setdefault(key, 0.0)
            sample.setdefault("loki_errors", 0.0)
            sample.setdefault("availability", 1.0)
        history.append(sample)
        await asyncio.sleep(15)


@app.on_event("startup")
async def startup() -> None:
    asyncio.create_task(collect_features())


@app.get("/features/latest")
async def latest() -> dict:
    return history[-1] if history else {}


@app.get("/features/history")
async def all_features() -> dict:
    return {"items": list(history)}

