from __future__ import annotations

import json
import os
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from services.shared.audit import audit_event
from services.shared.notifications import notify
from services.shared.observability import install_observability, observe_event, traced_get, traced_post
from services.shared.security import (
    get_controls,
    increment_security_metric,
    payload_has_xss,
    record_certificate_fingerprint,
    record_request,
    suspicious_forwarded_chain,
)

app = FastAPI(title="api-gateway")
logger = install_observability(app, "api-gateway")

ORDER_SERVICE = os.getenv("ORDER_SERVICE_URL", "http://order-service:8000")
RECOMMENDATION_SERVICE = os.getenv("RECOMMENDATION_SERVICE_URL", "http://recommendation-service:8000")
DDOS_RATE_LIMIT_PER_IP = int(os.getenv("DDOS_RATE_LIMIT_PER_IP", "20"))
XSS_PATTERN_STRICTNESS = os.getenv("XSS_PATTERN_STRICTNESS", "strict")
ALLOWED_ORIGINS = [item.strip() for item in os.getenv("SECURITY_ALLOWED_ORIGINS", "http://localhost,http://dashboard").split(",") if item.strip()]


class CheckoutRequest(BaseModel):
    user_id: str
    item_id: str
    quantity: int = 1


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    client = getattr(request, "client", None)
    return getattr(client, "host", None) or "unknown"


def request_payload_text(body: bytes, request: Request) -> str:
    query = request.url.query or ""
    header_subset = " ".join(f"{key}:{value}" for key, value in request.headers.items() if key.lower() in ("user-agent", "referer", "origin"))
    return " ".join(part for part in (query, header_subset, body.decode(errors="ignore")) if part)


async def reject_request(
    request: Request,
    status_code: int,
    detail: str,
    metric: str,
    classification: str,
) -> JSONResponse:
    increment_security_metric("api-gateway", metric)
    record_request("api-gateway", client_ip(request), request.url.path, blocked=True)
    audit_event(
        "api-gateway",
        "security-blocked-request",
        {"path": request.url.path, "detail": detail, "ip": client_ip(request)},
        severity="warning",
        status="blocked",
        target=request.url.path,
        classification=classification,
    )
    await notify(
        "api-gateway",
        "security_blocked_request",
        "warning",
        f"{classification} blocked on {request.url.path}",
        {"path": request.url.path, "detail": detail, "ip": client_ip(request)},
    )
    return JSONResponse(status_code=status_code, content={"detail": detail})


def mutation_request(request: Request) -> bool:
    return request.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}


def origin_allowed(request: Request) -> bool:
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")
    if not origin and not referer:
        return True
    return any(host in (origin or referer or "") for host in ALLOWED_ORIGINS)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    body = await request.body()
    ip = client_ip(request)
    controls = get_controls("api-gateway")
    record_request("api-gateway", ip, request.url.path)

    if suspicious_forwarded_chain(dict(request.headers)):
        return await reject_request(request, 400, "suspicious_proxy_headers", "tls_handshake_failures", "mitm_attack")

    if mutation_request(request) and not origin_allowed(request):
        return await reject_request(request, 403, "origin_not_allowed", "csrf_attempt_count", "csrf_attack")

    if controls.get("lockdown_mutations", {}).get("enabled") and mutation_request(request):
        return await reject_request(request, 423, "mutations_temporarily_locked", "csrf_attempt_count", "csrf_attack")

    payload_text = request_payload_text(body, request)
    waf_strict = XSS_PATTERN_STRICTNESS == "strict" or controls.get("waf_strict", {}).get("enabled")
    if payload_text and payload_has_xss(payload_text):
        increment_security_metric("api-gateway", "xss_attempt_count")
        if waf_strict:
            return await reject_request(request, 400, "xss_payload_rejected", "xss_attempt_count", "xss_attack")

    service_snapshot = record_request("api-gateway", ip, request.url.path)
    second = str(int(__import__("time").time()))
    ip_rate = int(service_snapshot.get("ip_buckets", {}).get(second, {}).get(ip, 0))
    if ip_rate > DDOS_RATE_LIMIT_PER_IP or controls.get("rate_limit", {}).get("enabled"):
        increment_security_metric("api-gateway", "blocked_attempt_count")
        return await reject_request(request, 429, "rate_limit_exceeded", "blocked_attempt_count", "ddos_attack")

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": body, "more_body": False}

    request._receive = receive
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["X-Frame-Options"] = "DENY"
    return response


@app.on_event("startup")
async def startup() -> None:
    expected = os.getenv("EXPECTED_SERVICE_CERT_FINGERPRINT", "")
    observed = os.getenv("OBSERVED_SERVICE_CERT_FINGERPRINT", expected)
    if observed:
        record_certificate_fingerprint("api-gateway", observed)
        if expected and observed != expected:
            increment_security_metric("api-gateway", "certificate_mismatch_count")
            increment_security_metric("api-gateway", "unexpected_certificate_fingerprint_count")


@app.post("/checkout")
async def checkout(request: CheckoutRequest) -> dict:
    if os.getenv("LOCKDOWN_MUTATIONS", "false").lower() == "true":
        raise HTTPException(status_code=423, detail="mutations_temporarily_locked")
    async with httpx.AsyncClient(timeout=5.0) as client:
        order_response = await traced_post(client, f"{ORDER_SERVICE}/orders", json=request.model_dump())
        order_response.raise_for_status()
        recs_response = await traced_get(client, f"{RECOMMENDATION_SERVICE}/recommendations/{request.user_id}")
        recs_response.raise_for_status()
    observe_event("api-gateway", "checkout_completed")
    logger.info("Checkout finished", extra={"user_id": request.user_id, "item_id": request.item_id})
    return {
        "order": order_response.json(),
        "recommendations": recs_response.json()["items"],
    }


@app.get("/security/status")
async def security_status() -> dict[str, Any]:
    controls = get_controls("api-gateway")
    return {
        "controls": controls,
        "rate_limit_per_ip": DDOS_RATE_LIMIT_PER_IP,
        "xss_mode": "strict" if XSS_PATTERN_STRICTNESS == "strict" or controls.get("waf_strict", {}).get("enabled") else "normal",
    }
