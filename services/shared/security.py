from __future__ import annotations

import os
import re
import time
from copy import deepcopy
from typing import Any

from services.shared.store import redis_client, redis_json_get, redis_json_set

SECURITY_WINDOW_SECONDS = int(os.getenv("SECURITY_WINDOW_SECONDS", "60"))
TRUSTED_PROXY_HOPS = int(os.getenv("TRUSTED_PROXY_HOPS", "2"))
KNOWN_PROXY_HEADERS = {
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "forwarded",
    "via",
}
XSS_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"<\s*script",
        r"javascript\s*:",
        r"on[a-z]+\s*=",
        r"%3c\s*script",
        r"%3c|%3e",
        r"document\s*\.\s*cookie",
        r"<\s*iframe",
    )
]
_MEMORY_STATE: dict[str, dict[str, Any]] = {}


def _now() -> int:
    return int(time.time())


def _default_service_state() -> dict[str, Any]:
    return {
        "last_seen": 0,
        "request_buckets": {},
        "ip_buckets": {},
        "endpoint_buckets": {},
        "security_buckets": {},
        "cert_fingerprints": [],
        "controls": {},
    }


def _cleanup_bucket_map(bucket_map: dict[str, Any], now: int) -> None:
    cutoff = now - SECURITY_WINDOW_SECONDS
    for key in list(bucket_map.keys()):
        try:
            if int(key) < cutoff:
                bucket_map.pop(key, None)
        except Exception:
            bucket_map.pop(key, None)


def _normalise_state(state: dict[str, Any] | None) -> dict[str, Any]:
    merged = _default_service_state()
    if isinstance(state, dict):
        merged.update(state)
    for key in ("request_buckets", "ip_buckets", "endpoint_buckets", "security_buckets", "controls"):
        if not isinstance(merged.get(key), dict):
            merged[key] = {}
    if not isinstance(merged.get("cert_fingerprints"), list):
        merged["cert_fingerprints"] = []
    return merged


def _service_key(service: str) -> str:
    return f"security:telemetry:{service}"


def _load_service_state(service: str) -> dict[str, Any]:
    try:
        state = redis_json_get(redis_client(), _service_key(service), None)
    except Exception:
        state = deepcopy(_MEMORY_STATE.get(service))
    return _normalise_state(state)


def _save_service_state(service: str, state: dict[str, Any]) -> None:
    state["last_seen"] = _now()
    try:
        redis_json_set(redis_client(), _service_key(service), state)
    except Exception:
        _MEMORY_STATE[service] = deepcopy(state)


def update_service_state(service: str, updater) -> dict[str, Any]:
    state = _load_service_state(service)
    now = _now()
    _cleanup_bucket_map(state["request_buckets"], now)
    _cleanup_bucket_map(state["ip_buckets"], now)
    _cleanup_bucket_map(state["endpoint_buckets"], now)
    _cleanup_bucket_map(state["security_buckets"], now)
    updater(state, now)
    _save_service_state(service, state)
    return state


def record_request(
    service: str,
    ip: str,
    endpoint: str,
    blocked: bool = False,
    header_alerts: list[str] | None = None,
) -> dict[str, Any]:
    ip_key = ip or "unknown"
    endpoint_key = endpoint or "/"
    alerts = header_alerts or []

    def updater(state: dict[str, Any], now: int) -> None:
        second = str(now)
        state["request_buckets"][second] = int(state["request_buckets"].get(second, 0)) + 1
        ip_bucket = state["ip_buckets"].setdefault(second, {})
        ip_bucket[ip_key] = int(ip_bucket.get(ip_key, 0)) + 1
        endpoint_bucket = state["endpoint_buckets"].setdefault(second, {})
        endpoint_bucket[endpoint_key] = int(endpoint_bucket.get(endpoint_key, 0)) + 1
        security_bucket = state["security_buckets"].setdefault(second, {})
        if blocked:
            security_bucket["blocked_attempt_count"] = int(security_bucket.get("blocked_attempt_count", 0)) + 1
        for alert in alerts:
            security_bucket[alert] = int(security_bucket.get(alert, 0)) + 1

    return update_service_state(service, updater)


def increment_security_metric(service: str, metric: str, amount: int = 1) -> dict[str, Any]:
    metric_key = metric.strip()

    def updater(state: dict[str, Any], now: int) -> None:
        second = str(now)
        security_bucket = state["security_buckets"].setdefault(second, {})
        security_bucket[metric_key] = int(security_bucket.get(metric_key, 0)) + amount

    return update_service_state(service, updater)


def record_certificate_fingerprint(service: str, fingerprint: str) -> dict[str, Any]:
    def updater(state: dict[str, Any], now: int) -> None:
        if fingerprint and fingerprint not in state["cert_fingerprints"]:
            state["cert_fingerprints"] = (state["cert_fingerprints"] + [fingerprint])[-5:]

    return update_service_state(service, updater)


def set_control(service: str, control: str, enabled: bool, ttl_seconds: int | None = None, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    ttl = ttl_seconds if ttl_seconds is not None else int(os.getenv("SECURITY_CONTROL_TTL_SECONDS", "300"))

    def updater(state: dict[str, Any], now: int) -> None:
        controls = state["controls"]
        if enabled:
            controls[control] = {
                "enabled": True,
                "expires_at": now + ttl if ttl > 0 else 0,
                "metadata": metadata or {},
            }
        else:
            controls.pop(control, None)

    return update_service_state(service, updater)


def get_controls(service: str) -> dict[str, dict[str, Any]]:
    state = _load_service_state(service)
    now = _now()
    controls = {}
    changed = False
    for name, payload in state.get("controls", {}).items():
        expires_at = int(payload.get("expires_at", 0) or 0)
        if expires_at and expires_at < now:
            changed = True
            continue
        controls[name] = payload
    if changed:
        state["controls"] = controls
        _save_service_state(service, state)
    return controls


def list_service_states() -> dict[str, dict[str, Any]]:
    items: dict[str, dict[str, Any]] = {}
    try:
        client = redis_client()
        for key in client.scan_iter(match="security:telemetry:*"):
            service = str(key).split("security:telemetry:", 1)[-1]
            items[service] = _normalise_state(redis_json_get(client, key, {}))
    except Exception:
        items = {service: deepcopy(state) for service, state in _MEMORY_STATE.items()}
    return items


def summarise_service_state(state: dict[str, Any]) -> dict[str, float]:
    now = _now()
    request_buckets = state.get("request_buckets", {})
    ip_buckets = state.get("ip_buckets", {})
    endpoint_buckets = state.get("endpoint_buckets", {})
    security_buckets = state.get("security_buckets", {})
    unique_ips: set[str] = set()
    request_total = 0
    max_ip_rate = 0
    endpoint_peak = 0
    metrics: dict[str, float] = {}
    for second in range(now - SECURITY_WINDOW_SECONDS + 1, now + 1):
        second_key = str(second)
        request_total += int(request_buckets.get(second_key, 0))
        ip_counts = ip_buckets.get(second_key, {})
        endpoint_counts = endpoint_buckets.get(second_key, {})
        if isinstance(ip_counts, dict):
            unique_ips.update(ip_counts.keys())
            max_ip_rate = max(max_ip_rate, *(int(value) for value in ip_counts.values()), default=max_ip_rate)
        if isinstance(endpoint_counts, dict):
            endpoint_peak = max(endpoint_peak, *(int(value) for value in endpoint_counts.values()), default=endpoint_peak)
        security_counts = security_buckets.get(second_key, {})
        if isinstance(security_counts, dict):
            for metric, value in security_counts.items():
                metrics[metric] = float(metrics.get(metric, 0.0) + float(value))
    connection_count = float(request_total)
    syn_flood_score = round(max_ip_rate / max(connection_count, 1.0), 4)
    metrics.update(
        {
            "requests_per_ip_per_second": float(max_ip_rate),
            "unique_source_ips": float(len(unique_ips)),
            "connection_count": connection_count,
            "syn_flood_score": syn_flood_score,
            "request_rate_peak_per_endpoint": float(endpoint_peak),
            "certificate_mismatch_count": float(metrics.get("certificate_mismatch_count", 0.0)),
            "tls_handshake_failures": float(metrics.get("tls_handshake_failures", 0.0)),
            "unexpected_certificate_fingerprints": float(metrics.get("unexpected_certificate_fingerprint_count", 0.0)),
            "xss_attempt_count": float(metrics.get("xss_attempt_count", 0.0)),
            "clickjack_attempt_count": float(metrics.get("clickjack_attempt_count", 0.0)),
            "csrf_attempt_count": float(metrics.get("csrf_attempt_count", 0.0)),
            "blocked_attempt_count": float(metrics.get("blocked_attempt_count", 0.0)),
        }
    )
    metrics["active_mitigations"] = float(len(get_controls(state.get("service_name", ""))) if state.get("service_name") else len(state.get("controls", {})))
    return metrics


def cluster_security_snapshot(services: list[str] | None = None) -> tuple[dict[str, float], dict[str, dict[str, float]]]:
    aggregate: dict[str, float] = {}
    per_service: dict[str, dict[str, float]] = {}
    loaded = list_service_states()
    for service, raw_state in loaded.items():
        if services and service not in services:
            continue
        state = _normalise_state(raw_state)
        state["service_name"] = service
        summary = summarise_service_state(state)
        per_service[service] = summary
        for key, value in summary.items():
            aggregate[key] = float(aggregate.get(key, 0.0) + value)
    if per_service:
        aggregate["requests_per_ip_per_second"] = max(
            (item.get("requests_per_ip_per_second", 0.0) for item in per_service.values()),
            default=0.0,
        )
        aggregate["syn_flood_score"] = max((item.get("syn_flood_score", 0.0) for item in per_service.values()), default=0.0)
        aggregate["request_rate_peak_per_endpoint"] = max(
            (item.get("request_rate_peak_per_endpoint", 0.0) for item in per_service.values()),
            default=0.0,
        )
    return aggregate, per_service


def suspicious_forwarded_chain(headers: dict[str, str]) -> bool:
    chain = [item.strip() for item in headers.get("x-forwarded-for", "").split(",") if item.strip()]
    if len(chain) > TRUSTED_PROXY_HOPS + 1:
        return True
    if headers.get("forwarded") and not headers.get("x-forwarded-for"):
        return True
    return False


def suspicious_embedding_request(headers: dict[str, str], allowed_hosts: list[str]) -> bool:
    origin = headers.get("origin", "")
    referer = headers.get("referer", "")
    checks = [origin, referer]
    for value in checks:
        if not value:
            continue
        if not any(host in value for host in allowed_hosts):
            return True
    return False


def payload_has_xss(payload: str) -> bool:
    return any(pattern.search(payload) for pattern in XSS_PATTERNS)
