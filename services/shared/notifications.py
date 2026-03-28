from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timezone
from threading import Lock
from typing import Any

import httpx

from services.shared.config import env, env_bool
from services.shared.store import ensure_table, pg_conn

SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}
logger = logging.getLogger("platform-notifications")
_queue_ready = False
_queue_lock = Lock()

NOTIFICATION_DDL = """
CREATE TABLE IF NOT EXISTS notification_delivery_queue (
    id BIGSERIAL PRIMARY KEY,
    dedupe_key TEXT NOT NULL UNIQUE,
    provider TEXT NOT NULL,
    target TEXT NOT NULL,
    payload JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
"""

NOTIFICATION_INDEX_DDL = """
CREATE INDEX IF NOT EXISTS idx_notification_delivery_queue_status_next_attempt
ON notification_delivery_queue(status, next_attempt_at)
"""


def ensure_notification_tables() -> None:
    global _queue_ready
    if _queue_ready:
        return
    with _queue_lock:
        if _queue_ready:
            return
        with pg_conn() as connection:
            ensure_table(connection, NOTIFICATION_DDL)
            ensure_table(connection, NOTIFICATION_INDEX_DDL)
        _queue_ready = True


def severity_at_least(severity: str, minimum: str) -> bool:
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(minimum, 0)


def should_notify(severity: str) -> bool:
    if not env_bool("ALERTING_ENABLED", False):
        return False
    return severity_at_least(severity, env("ALERT_MIN_SEVERITY", "warning"))


def notification_targets(severity: str) -> list[str]:
    urls = []
    specific = {
        "info": env("ALERT_WEBHOOK_INFO_URL", ""),
        "warning": env("ALERT_WEBHOOK_WARNING_URL", ""),
        "critical": env("ALERT_WEBHOOK_CRITICAL_URL", ""),
    }.get(severity, "")
    if specific:
        urls.append(specific)
    shared = env("ALERT_WEBHOOK_URL", "")
    if shared:
        urls.append(shared)
    deduped: list[str] = []
    for url in urls:
        if url and url not in deduped:
            deduped.append(url)
    return deduped


def slack_target() -> str:
    return env("SLACK_WEBHOOK_URL", "")


def pagerduty_target() -> str:
    return env("PAGERDUTY_EVENTS_URL", "")


def alertmanager_target() -> str:
    return env("ALERTMANAGER_URL", "")


def slack_payload(body: dict[str, Any]) -> dict[str, Any]:
    return {
        "text": body["text"],
        "attachments": [
            {
                "color": {"info": "#439FE0", "warning": "#f4a261", "critical": "#df3f54"}.get(body["severity"], "#439FE0"),
                "title": body["title"],
                "fields": [
                    {"title": "Source", "value": body["source"], "short": True},
                    {"title": "Severity", "value": body["severity"], "short": True},
                    {"title": "Event", "value": body["event_type"], "short": True},
                ],
                "ts": int(datetime.now(timezone.utc).timestamp()),
            }
        ],
    }


def pagerduty_payload(body: dict[str, Any]) -> dict[str, Any]:
    return {
        "routing_key": env("PAGERDUTY_ROUTING_KEY", ""),
        "event_action": "trigger",
        "payload": {
            "summary": body["text"],
            "severity": "error" if body["severity"] == "critical" else "warning",
            "source": body["source"],
            "component": body["event_type"],
            "custom_details": body["payload"],
        },
    }


def alertmanager_payload(body: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "status": "firing",
            "labels": {
                "alertname": body["event_type"],
                "severity": body["severity"],
                "service": body["source"],
            },
            "annotations": {
                "summary": body["title"],
                "description": body["text"],
            },
            "startsAt": body["ts"],
            "generatorURL": body["source"],
        }
    ]


def dedupe_key(provider: str, target: str, body: dict[str, Any]) -> str:
    raw = json.dumps({"provider": provider, "target": target, "event": body["event_type"], "severity": body["severity"], "title": body["title"]}, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def enqueue_notification(provider: str, target: str, body: dict[str, Any]) -> None:
    ensure_notification_tables()
    key = dedupe_key(provider, target, body)
    try:
        with pg_conn() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO notification_delivery_queue (dedupe_key, provider, target, payload)
                VALUES (%s, %s, %s, %s::jsonb)
                ON CONFLICT (dedupe_key) DO NOTHING
                """,
                (key, provider, target, json.dumps(body)),
            )
    except Exception as exc:
        logger.warning("Notification queue enqueue failed", extra={"provider": provider, "target": target, "error": str(exc)})


def next_pending_notifications(limit: int = 10) -> list[dict[str, Any]]:
    ensure_notification_tables()
    try:
        with pg_conn() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, provider, target, payload, attempts
                FROM notification_delivery_queue
                WHERE status IN ('pending', 'retrying') AND next_attempt_at <= NOW()
                ORDER BY id ASC
                LIMIT %s
                """,
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]
    except Exception as exc:
        logger.warning("Notification queue fetch failed", extra={"error": str(exc)})
        return []


def mark_delivery_result(item_id: int, status: str, *, error: str | None = None, attempts: int = 0) -> None:
    ensure_notification_tables()
    next_delay_minutes = min(30, max(1, 2 ** max(attempts - 1, 0)))
    try:
        with pg_conn() as connection, connection.cursor() as cursor:
            if status == "sent":
                cursor.execute(
                    """
                    UPDATE notification_delivery_queue
                    SET status = 'sent', attempts = %s, last_error = NULL, updated_at = NOW()
                    WHERE id = %s
                    """,
                    (attempts, item_id),
                )
            else:
                cursor.execute(
                    """
                    UPDATE notification_delivery_queue
                    SET status = 'retrying', attempts = %s, last_error = %s,
                        next_attempt_at = NOW() + (%s || ' minutes')::interval,
                        updated_at = NOW()
                    WHERE id = %s
                    """,
                    (attempts, error, next_delay_minutes, item_id),
                )
    except Exception as exc:
        logger.warning("Notification queue update failed", extra={"id": item_id, "status": status, "error": str(exc)})


async def deliver(provider: str, target: str, body: dict[str, Any]) -> None:
    async with httpx.AsyncClient(timeout=4.0) as client:
        if provider == "webhook":
            response = await client.post(target, json=body)
        elif provider == "slack":
            response = await client.post(target, json=slack_payload(body))
        elif provider == "pagerduty":
            response = await client.post(target, json=pagerduty_payload(body))
        elif provider == "alertmanager":
            response = await client.post(target, json=alertmanager_payload(body))
        else:
            raise RuntimeError(f"unknown_provider:{provider}")
        response.raise_for_status()


async def flush_notification_queue(limit: int = 10) -> list[dict[str, Any]]:
    results = []
    for item in next_pending_notifications(limit):
        attempts = int(item.get("attempts", 0)) + 1
        try:
            await deliver(str(item["provider"]), str(item["target"]), dict(item["payload"]))
            mark_delivery_result(int(item["id"]), "sent", attempts=attempts)
            results.append({"id": item["id"], "status": "sent"})
        except Exception as exc:
            mark_delivery_result(int(item["id"]), "retrying", error=str(exc), attempts=attempts)
            results.append({"id": item["id"], "status": "retrying", "error": str(exc)})
    return results


async def notification_worker(poll_seconds: float = 15.0) -> None:
    while True:
        try:
            await flush_notification_queue()
        except Exception as exc:
            logger.warning("Notification worker flush failed", extra={"error": str(exc)})
        await asyncio.sleep(poll_seconds)


async def notify(
    source: str,
    event_type: str,
    severity: str,
    title: str,
    payload: dict[str, Any],
) -> list[dict[str, Any]]:
    if not should_notify(severity):
        return []
    results = []
    body = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "event_type": event_type,
        "severity": severity,
        "title": title,
        "payload": payload,
        "text": f"[{severity.upper()}] {source}: {title}",
    }
    for url in notification_targets(severity):
        enqueue_notification("webhook", url, body)
        results.append({"url": url, "provider": "webhook", "status": "queued"})
    if slack_target():
        enqueue_notification("slack", slack_target(), body)
        results.append({"url": slack_target(), "provider": "slack", "status": "queued"})
    if pagerduty_target() and env("PAGERDUTY_ROUTING_KEY", ""):
        enqueue_notification("pagerduty", pagerduty_target(), body)
        results.append({"url": pagerduty_target(), "provider": "pagerduty", "status": "queued"})
    if alertmanager_target():
        enqueue_notification("alertmanager", alertmanager_target(), body)
        results.append({"url": alertmanager_target(), "provider": "alertmanager", "status": "queued"})
    results.extend(await flush_notification_queue())
    return results
