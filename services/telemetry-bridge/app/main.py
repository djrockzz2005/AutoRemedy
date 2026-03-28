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
from services.shared.security import cluster_security_snapshot

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
    "requests_per_ip_per_second": 'sum(platform_security_requests_per_ip_per_second)',
    "unique_source_ips": 'sum(platform_security_unique_source_ips)',
    "connection_count": 'sum(platform_security_connection_count)',
    "syn_flood_score": 'sum(platform_security_syn_flood_score)',
    "tls_handshake_failures": 'sum(platform_security_tls_handshake_failures_total)',
    "certificate_mismatch_count": 'sum(platform_security_certificate_mismatch_total)',
    "unexpected_certificate_fingerprints": 'sum(platform_security_unexpected_certificate_fingerprint_total)',
    "xss_attempt_count": 'sum(platform_security_xss_attempt_total)',
    "clickjack_attempt_count": 'sum(platform_security_clickjacking_attempt_total)',
    "csrf_attempt_count": 'sum(platform_security_csrf_attempt_total)',
    "blocked_attempt_count": 'sum(platform_security_blocked_attempt_total)',
    "request_rate_peak_per_endpoint": 'sum(platform_security_request_rate_peak_per_endpoint)',
    "active_mitigations": 'sum(platform_security_active_mitigations)',
    "session_hijack_attempt_count": 'sum(platform_security_session_hijack_attempt_total)',
    "credential_stuffing_attempt_count": 'sum(platform_security_credential_stuffing_attempt_total)',
    "sqli_attempt_count": 'sum(platform_security_sqli_attempt_total)',
    "tls_downgrade_attempt_count": 'sum(platform_security_tls_downgrade_attempt_total)',
    "dns_spoof_attempt_count": 'sum(platform_security_dns_spoof_attempt_total)',
    "arp_spoof_attempt_count": 'sum(platform_security_arp_spoof_attempt_total)',
    "rogue_wifi_attempt_count": 'sum(platform_security_rogue_wifi_attempt_total)',
    "aitm_phishing_attempt_count": 'sum(platform_security_aitm_attempt_total)',
    "supply_chain_risk_count": 'sum(platform_security_supply_chain_risk_total)',
    "zero_day_signal_count": 'sum(platform_security_zero_day_signal_total)',
    "credential_target_count": 'sum(platform_security_credential_target_total)',
}

PER_SERVICE_QUERIES = {
    "request_rate": 'sum by (service) (rate(platform_http_requests_total{status!~"5.."}[1m]))',
    "error_rate": 'sum by (service) (rate(platform_http_requests_total{status=~"5.."}[1m]))',
    "latency_p95": 'histogram_quantile(0.95, sum by (service, le) (rate(platform_http_request_duration_seconds_bucket[5m])))',
    "restarts": 'sum by (service) (label_replace(kube_pod_container_status_restarts_total{namespace="chaos-loop",container!=""}, "service", "$1", "container", "(.*)"))',
    "cpu": 'sum by (service) (label_replace(rate(container_cpu_usage_seconds_total{namespace="chaos-loop",container!=""}[1m]), "service", "$1", "container", "(.*)"))',
    "memory": 'sum by (service) (label_replace(container_memory_working_set_bytes{namespace="chaos-loop",container!=""}, "service", "$1", "container", "(.*)"))',
    "requests_per_ip_per_second": 'sum by (service) (platform_security_requests_per_ip_per_second)',
    "unique_source_ips": 'sum by (service) (platform_security_unique_source_ips)',
    "connection_count": 'sum by (service) (platform_security_connection_count)',
    "syn_flood_score": 'sum by (service) (platform_security_syn_flood_score)',
    "tls_handshake_failures": 'sum by (service) (platform_security_tls_handshake_failures_total)',
    "certificate_mismatch_count": 'sum by (service) (platform_security_certificate_mismatch_total)',
    "unexpected_certificate_fingerprints": 'sum by (service) (platform_security_unexpected_certificate_fingerprint_total)',
    "xss_attempt_count": 'sum by (service) (platform_security_xss_attempt_total)',
    "clickjack_attempt_count": 'sum by (service) (platform_security_clickjacking_attempt_total)',
    "csrf_attempt_count": 'sum by (service) (platform_security_csrf_attempt_total)',
    "blocked_attempt_count": 'sum by (service) (platform_security_blocked_attempt_total)',
    "request_rate_peak_per_endpoint": 'sum by (service) (platform_security_request_rate_peak_per_endpoint)',
    "active_mitigations": 'sum by (service) (platform_security_active_mitigations)',
    "session_hijack_attempt_count": 'sum by (service) (platform_security_session_hijack_attempt_total)',
    "credential_stuffing_attempt_count": 'sum by (service) (platform_security_credential_stuffing_attempt_total)',
    "sqli_attempt_count": 'sum by (service) (platform_security_sqli_attempt_total)',
    "tls_downgrade_attempt_count": 'sum by (service) (platform_security_tls_downgrade_attempt_total)',
    "dns_spoof_attempt_count": 'sum by (service) (platform_security_dns_spoof_attempt_total)',
    "arp_spoof_attempt_count": 'sum by (service) (platform_security_arp_spoof_attempt_total)',
    "rogue_wifi_attempt_count": 'sum by (service) (platform_security_rogue_wifi_attempt_total)',
    "aitm_phishing_attempt_count": 'sum by (service) (platform_security_aitm_attempt_total)',
    "supply_chain_risk_count": 'sum by (service) (platform_security_supply_chain_risk_total)',
    "zero_day_signal_count": 'sum by (service) (platform_security_zero_day_signal_total)',
    "credential_target_count": 'sum by (service) (platform_security_credential_target_total)',
}

SECURITY_SLO_DEFAULTS = {
    "xss_attempt_rate_max": 0.0,
    "ddos_block_rate_min": 0.99,
    "csrf_attempt_rate_max": 0.0,
    "clickjack_attempt_rate_max": 0.0,
    "tls_handshake_failures_max": 0.0,
    "credential_stuffing_attempt_rate_max": 0.0,
    "sqli_attempt_rate_max": 0.0,
    "session_hijack_attempt_rate_max": 0.0,
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


def apply_security_snapshot(
    aggregate_sample: dict[str, Any],
    per_service_metrics: dict[str, dict[str, float]],
) -> tuple[dict[str, Any], dict[str, dict[str, float]]]:
    aggregate_security, per_service_security = cluster_security_snapshot(list(per_service_metrics.keys()) or None)
    for key, value in aggregate_security.items():
        aggregate_sample[key] = float(value)
    for service, security_metrics in per_service_security.items():
        target = per_service_metrics.setdefault(service, {})
        for key, value in security_metrics.items():
            target[key] = float(value)
    return aggregate_sample, per_service_metrics


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
        ddos_block_rate_min = float(targets.get("ddos_block_rate_min", SECURITY_SLO_DEFAULTS["ddos_block_rate_min"]))
        xss_attempt_rate_max = float(targets.get("xss_attempt_rate_max", SECURITY_SLO_DEFAULTS["xss_attempt_rate_max"]))
        csrf_attempt_rate_max = float(targets.get("csrf_attempt_rate_max", SECURITY_SLO_DEFAULTS["csrf_attempt_rate_max"]))
        clickjack_attempt_rate_max = float(
            targets.get("clickjack_attempt_rate_max", SECURITY_SLO_DEFAULTS["clickjack_attempt_rate_max"])
        )
        tls_handshake_failures_max = float(
            targets.get("tls_handshake_failures_max", SECURITY_SLO_DEFAULTS["tls_handshake_failures_max"])
        )
        credential_stuffing_attempt_rate_max = float(
            targets.get("credential_stuffing_attempt_rate_max", SECURITY_SLO_DEFAULTS["credential_stuffing_attempt_rate_max"])
        )
        sqli_attempt_rate_max = float(targets.get("sqli_attempt_rate_max", SECURITY_SLO_DEFAULTS["sqli_attempt_rate_max"]))
        session_hijack_attempt_rate_max = float(
            targets.get("session_hijack_attempt_rate_max", SECURITY_SLO_DEFAULTS["session_hijack_attempt_rate_max"])
        )
        latency_ok = observed.get("latency_p95", 0.0) <= latency_target
        error_ok = observed.get("error_rate", 0.0) <= error_target
        availability_ok = observed.get("availability", 1.0) >= availability_target
        xss_ok = observed.get("xss_attempt_count", 0.0) <= xss_attempt_rate_max
        csrf_ok = observed.get("csrf_attempt_count", 0.0) <= csrf_attempt_rate_max
        clickjack_ok = observed.get("clickjack_attempt_count", 0.0) <= clickjack_attempt_rate_max
        tls_ok = observed.get("tls_handshake_failures", 0.0) <= tls_handshake_failures_max
        credential_stuffing_ok = observed.get("credential_stuffing_attempt_count", 0.0) <= credential_stuffing_attempt_rate_max
        sqli_ok = observed.get("sqli_attempt_count", 0.0) <= sqli_attempt_rate_max
        session_hijack_ok = observed.get("session_hijack_attempt_count", 0.0) <= session_hijack_attempt_rate_max
        total_connections = max(observed.get("connection_count", 0.0), 1.0)
        ddos_block_rate = observed.get("blocked_attempt_count", 0.0) / total_connections if total_connections > 0 else 1.0
        ddos_ok = ddos_block_rate >= ddos_block_rate_min or observed.get("requests_per_ip_per_second", 0.0) == 0.0
        checks = [
            ("latency_p95", latency_ok),
            ("error_rate", error_ok),
            ("availability", availability_ok),
            ("xss_attempt_count", xss_ok),
            ("csrf_attempt_count", csrf_ok),
            ("clickjack_attempt_count", clickjack_ok),
            ("tls_handshake_failures", tls_ok),
            ("credential_stuffing_attempt_count", credential_stuffing_ok),
            ("sqli_attempt_count", sqli_ok),
            ("session_hijack_attempt_count", session_hijack_ok),
            ("ddos_block_rate", ddos_ok),
        ]
        passed = sum(1 for _, ok in checks if ok)
        compliance = round((passed / len(checks)) * 100.0, 2)
        violations = [name for name, ok in checks if not ok]
        burn_rate = round(
            max(
                observed.get("latency_p95", 0.0) / max(latency_target, 0.0001),
                observed.get("error_rate", 0.0) / max(error_target, 0.0001),
                availability_target / max(observed.get("availability", 0.0001), 0.0001),
                observed.get("xss_attempt_count", 0.0) / max(xss_attempt_rate_max + 0.0001, 0.0001),
                observed.get("csrf_attempt_count", 0.0) / max(csrf_attempt_rate_max + 0.0001, 0.0001),
                observed.get("clickjack_attempt_count", 0.0) / max(clickjack_attempt_rate_max + 0.0001, 0.0001),
                observed.get("tls_handshake_failures", 0.0) / max(tls_handshake_failures_max + 0.0001, 0.0001),
                observed.get("credential_stuffing_attempt_count", 0.0)
                / max(credential_stuffing_attempt_rate_max + 0.0001, 0.0001),
                observed.get("sqli_attempt_count", 0.0) / max(sqli_attempt_rate_max + 0.0001, 0.0001),
                observed.get("session_hijack_attempt_count", 0.0)
                / max(session_hijack_attempt_rate_max + 0.0001, 0.0001),
                ddos_block_rate_min / max(ddos_block_rate, 0.0001),
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
                        "ddos_block_rate_min": ddos_block_rate_min,
                        "xss_attempt_rate_max": xss_attempt_rate_max,
                        "csrf_attempt_rate_max": csrf_attempt_rate_max,
                        "clickjack_attempt_rate_max": clickjack_attempt_rate_max,
                        "tls_handshake_failures_max": tls_handshake_failures_max,
                        "credential_stuffing_attempt_rate_max": credential_stuffing_attempt_rate_max,
                        "sqli_attempt_rate_max": sqli_attempt_rate_max,
                        "session_hijack_attempt_rate_max": session_hijack_attempt_rate_max,
                    },
                "observed": {**observed, "ddos_block_rate": round(ddos_block_rate, 4)},
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
                sample, latest_per_service = apply_security_snapshot(sample, latest_per_service)
                sample["per_service"] = latest_per_service
        except Exception as exc:
            sample["collector_error"] = str(exc)
            logger.warning("Telemetry collection degraded", extra={"error": str(exc)})
            for key in QUERIES:
                sample.setdefault(key, 0.0)
            sample.setdefault("loki_errors", 0.0)
            sample.setdefault("availability", 1.0)
            for key in QUERIES:
                sample.setdefault(key, 0.0)
            sample, latest_per_service = apply_security_snapshot(sample, latest_per_service)
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
