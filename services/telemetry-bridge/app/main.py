from __future__ import annotations

import asyncio
import os
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI
import yaml

from services.shared.history import record_history, recent_history
from services.shared.observability import install_observability

app = FastAPI(title="telemetry-bridge")
logger = install_observability(app, "telemetry-bridge")

PROM_URL = os.getenv("PROMETHEUS_URL", "http://prometheus:9090")
LOKI_URL = os.getenv("LOKI_URL", "http://loki:3100")
WINDOW = int(os.getenv("FEATURE_WINDOW", "120"))
COLLECT_INTERVAL = float(os.getenv("COLLECT_INTERVAL_SECONDS", "2"))
history: deque[dict] = deque(maxlen=WINDOW)
latest_per_service: dict[str, dict[str, float]] = {}
SLO_PATH = Path(os.getenv("SLO_PATH", "/app/config/slos.yaml"))

QUERIES = {
    "request_rate": 'sum(rate(platform_http_requests_total{status!~"5.."}[1m]))',
    "error_rate": 'sum(rate(platform_http_requests_total{status=~"5.."}[1m]))',
    "latency_p95": 'histogram_quantile(0.95, sum(rate(platform_http_request_duration_seconds_bucket[5m])) by (le))',
    "restarts": 'sum(label_replace(kube_pod_container_status_restarts_total{namespace="chaos-loop",container!=""}, "service", "$1", "container", "(.*)"))',
    "cpu": 'sum(label_replace(rate(container_cpu_usage_seconds_total{namespace="chaos-loop",container!=""}[1m]), "service", "$1", "container", "(.*)"))',
    "memory": 'sum(label_replace(container_memory_working_set_bytes{namespace="chaos-loop",container!=""}, "service", "$1", "container", "(.*)"))',
}

PER_SERVICE_QUERIES = {
    "request_rate": 'sum by (service) (rate(platform_http_requests_total{status!~"5.."}[1m]))',
    "error_rate": 'sum by (service) (rate(platform_http_requests_total{status=~"5.."}[1m]))',
    "latency_p95": 'histogram_quantile(0.95, sum by (service, le) (rate(platform_http_request_duration_seconds_bucket[5m])))',
    "restarts": 'sum by (service) (label_replace(kube_pod_container_status_restarts_total{namespace="chaos-loop",container!=""}, "service", "$1", "container", "(.*)"))',
    "cpu": 'sum by (service) (label_replace(rate(container_cpu_usage_seconds_total{namespace="chaos-loop",container!=""}[1m]), "service", "$1", "container", "(.*)"))',
    "memory": 'sum by (service) (label_replace(container_memory_working_set_bytes{namespace="chaos-loop",container!=""}, "service", "$1", "container", "(.*)"))',
}


async def prom_query(client: httpx.AsyncClient, query: str) -> float:
    response = await client.get(f"{PROM_URL}/api/v1/query", params={"query": query})
    response.raise_for_status()
    payload = response.json()
    result = payload.get("data", {}).get("result", [])
    if not result:
        return 0.0
    return float(result[0]["value"][1])


async def prom_query_grouped(client: httpx.AsyncClient, query: str, label: str = "service") -> dict[str, float]:
    response = await client.get(f"{PROM_URL}/api/v1/query", params={"query": query})
    response.raise_for_status()
    payload = response.json()
    items = payload.get("data", {}).get("result", [])
    grouped: dict[str, float] = {}
    for item in items:
        key = item.get("metric", {}).get(label)
        if not key:
            continue
        grouped[key] = float(item["value"][1])
    return grouped


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


async def loki_error_count_per_service(client: httpx.AsyncClient) -> dict[str, float]:
    now_ns = int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)
    params = {
        "query": 'sum by (service) (count_over_time({service=~".+"} |= "error" [1m]))',
        "start": str(now_ns - 60_000_000_000),
        "end": str(now_ns),
    }
    response = await client.get(f"{LOKI_URL}/loki/api/v1/query", params=params)
    response.raise_for_status()
    result = response.json().get("data", {}).get("result", [])
    grouped: dict[str, float] = {}
    for item in result:
        service = item.get("metric", {}).get("service")
        if not service:
            continue
        grouped[service] = float(item["value"][1])
    return grouped


def merge_per_service(samples: dict[str, dict[str, float]], services: set[str]) -> dict[str, dict[str, float]]:
    merged: dict[str, dict[str, float]] = {}
    for service in sorted(services):
        item = {name: float(samples.get(name, {}).get(service, 0.0)) for name in PER_SERVICE_QUERIES}
        total = item["request_rate"] + item["error_rate"]
        item["availability"] = 1.0 if total == 0 else item["request_rate"] / total
        item["loki_errors"] = float(samples.get("loki_errors", {}).get(service, 0.0))
        merged[service] = item
    return merged


def load_slos() -> dict[str, dict[str, float]]:
    if not SLO_PATH.exists():
        return {}
    try:
        payload = yaml.safe_load(SLO_PATH.read_text()) or {}
    except Exception as exc:
        logger.warning("Failed to load SLO config", extra={"path": str(SLO_PATH), "error": str(exc)})
        return {}
    services = payload.get("services", payload)
    return services if isinstance(services, dict) else {}


def evaluate_slos(metrics: dict[str, dict[str, float]], slos: dict[str, dict[str, float]]) -> dict[str, Any]:
    items = []
    for service, targets in slos.items():
        observed = metrics.get(service, {})
        latency_target = float(targets.get("latency_p95_max", 0.5))
        error_target = float(targets.get("error_rate_max", 0.05))
        availability_target = float(targets.get("availability_min", 0.99))
        latency_ok = observed.get("latency_p95", 0.0) <= latency_target
        error_ok = observed.get("error_rate", 0.0) <= error_target
        availability_ok = observed.get("availability", 1.0) >= availability_target
        checks = [
            ("latency_p95", latency_ok),
            ("error_rate", error_ok),
            ("availability", availability_ok),
        ]
        passed = sum(1 for _, ok in checks if ok)
        compliance = round((passed / len(checks)) * 100.0, 2)
        violations = [name for name, ok in checks if not ok]
        burn_rate = round(
            max(
                observed.get("latency_p95", 0.0) / max(latency_target, 0.0001),
                observed.get("error_rate", 0.0) / max(error_target, 0.0001),
                availability_target / max(observed.get("availability", 0.0001), 0.0001),
            ),
            3,
        )
        items.append(
            {
                "service": service,
                "compliance": compliance,
                "healthy": not violations,
                "violations": violations,
                "burn_rate": burn_rate,
                "targets": {
                    "latency_p95_max": latency_target,
                    "error_rate_max": error_target,
                    "availability_min": availability_target,
                },
                "observed": observed,
            }
        )
    overall = round(sum(item["compliance"] for item in items) / len(items), 2) if items else 100.0
    return {"ts": datetime.now(timezone.utc).isoformat(), "overall_compliance": overall, "items": items}


async def collect_features() -> None:
    global latest_per_service
    while True:
        sample = {"ts": datetime.now(timezone.utc).isoformat()}
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                for key, query in QUERIES.items():
                    sample[key] = await prom_query(client, query)
                sample["loki_errors"] = await loki_error_count(client)
                total = sample["request_rate"] + sample["error_rate"]
                sample["availability"] = 1.0 if total == 0 else sample["request_rate"] / total
                per_service_raw = {
                    key: await prom_query_grouped(client, query) for key, query in PER_SERVICE_QUERIES.items()
                }
                per_service_raw["loki_errors"] = await loki_error_count_per_service(client)
                services = set()
                for values in per_service_raw.values():
                    services.update(values.keys())
                latest_per_service = merge_per_service(per_service_raw, services)
                sample["per_service"] = latest_per_service
        except Exception as exc:
            sample["collector_error"] = str(exc)
            logger.warning("Telemetry collection degraded", extra={"error": str(exc)})
            for key in QUERIES:
                sample.setdefault(key, 0.0)
            sample.setdefault("loki_errors", 0.0)
            sample.setdefault("availability", 1.0)
            sample["per_service"] = latest_per_service
        history.append(sample)
        record_history("telemetry-history", "telemetry-bridge", sample)
        await asyncio.sleep(COLLECT_INTERVAL)


@app.on_event("startup")
async def startup() -> None:
    asyncio.create_task(collect_features())


@app.get("/features/latest")
async def latest() -> dict:
    return history[-1] if history else {}


@app.get("/features/history")
async def all_features() -> dict:
    return {"items": recent_history("telemetry-history", WINDOW) or list(history)}


@app.get("/features/per-service")
async def per_service() -> dict[str, Any]:
    latest = history[-1] if history else {}
    return {
        "ts": latest.get("ts"),
        "items": latest_per_service,
    }


@app.get("/slo/status")
async def slo_status() -> dict[str, Any]:
    return evaluate_slos(latest_per_service, load_slos())
