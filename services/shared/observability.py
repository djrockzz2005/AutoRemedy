from __future__ import annotations

import asyncio
import logging
import os
import socket
import time
from datetime import datetime, timezone
from logging import Handler, LogRecord

import httpx
from fastapi import FastAPI, Request
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from pythonjsonlogger import jsonlogger
from starlette.responses import Response

from services.shared.config import env, env_int

REQUEST_COUNT = Counter(
    "platform_http_requests_total",
    "HTTP requests",
    ["service", "method", "path", "status"],
)
REQUEST_LATENCY = Histogram(
    "platform_http_request_duration_seconds",
    "HTTP request latency",
    ["service", "method", "path"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10),
)
DOMAIN_EVENTS = Counter(
    "platform_domain_events_total",
    "Business events",
    ["service", "event"],
)


class LokiHandler(Handler):
    def __init__(self) -> None:
        super().__init__()
        self.endpoint = os.getenv("LOKI_PUSH_URL", "http://loki:3100/loki/api/v1/push")
        self.service_name = os.getenv("SERVICE_NAME", "unknown")
        self.host = socket.gethostname()

    def emit(self, record: LogRecord) -> None:
        payload = {
            "streams": [
                {
                    "stream": {
                        "service": self.service_name,
                        "host": self.host,
                        "level": record.levelname.lower(),
                    },
                    "values": [
                        [
                            str(int(time.time() * 1_000_000_000)),
                            self.format(record),
                        ]
                    ],
                }
            ]
        }
        try:
            with httpx.Client(timeout=0.5) as client:
                client.post(self.endpoint, json=payload)
        except Exception:
            pass


def configure_logging(service_name: str) -> logging.Logger:
    logger = logging.getLogger(service_name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    formatter = jsonlogger.JsonFormatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    loki = LokiHandler()
    loki.setFormatter(formatter)
    logger.addHandler(loki)
    logger.propagate = False
    return logger


def observe_event(service_name: str, event_name: str) -> None:
    DOMAIN_EVENTS.labels(service=service_name, event=event_name).inc()


def install_observability(app: FastAPI, service_name: str) -> logging.Logger:
    logger = configure_logging(service_name)

    @app.middleware("http")
    async def metrics_middleware(request: Request, call_next):
        path = request.url.path
        latency_ms = env_int("LATENCY_MS", 0)
        if latency_ms > 0:
            await asyncio.sleep(latency_ms / 1000.0)
        started = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            return response
        except Exception:
            logger.exception("Unhandled request error", extra={"path": path})
            raise
        finally:
            elapsed = time.perf_counter() - started
            REQUEST_COUNT.labels(
                service=service_name,
                method=request.method,
                path=path,
                status=str(status),
            ).inc()
            REQUEST_LATENCY.labels(
                service=service_name,
                method=request.method,
                path=path,
            ).observe(elapsed)

    @app.get("/metrics")
    async def metrics() -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @app.get("/healthz")
    async def healthz() -> dict:
        return {
            "service": service_name,
            "status": "ok",
            "time": datetime.now(timezone.utc).isoformat(),
        }

    return logger

