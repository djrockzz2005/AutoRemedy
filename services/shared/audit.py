from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from threading import Lock
from typing import Any

from services.shared.store import ensure_table, pg_conn

logger = logging.getLogger("platform-audit")
_table_ready = False
_table_lock = Lock()

AUDIT_DDL = """
CREATE TABLE IF NOT EXISTS platform_audit_log (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL,
    source TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT,
    target TEXT,
    classification TEXT,
    actor TEXT,
    payload JSONB NOT NULL
)
"""

AUDIT_INDEX_DDL = """
CREATE INDEX IF NOT EXISTS idx_platform_audit_log_ts_category
ON platform_audit_log(ts DESC, category, source)
"""


def ensure_audit_table() -> None:
    global _table_ready
    if _table_ready:
        return
    with _table_lock:
        if _table_ready:
            return
        with pg_conn() as connection:
            ensure_table(connection, AUDIT_DDL)
            ensure_table(connection, AUDIT_INDEX_DDL)
        _table_ready = True


def audit_event(
    source: str,
    category: str,
    payload: dict[str, Any],
    *,
    severity: str = "info",
    status: str | None = None,
    target: str | None = None,
    classification: str | None = None,
    actor: str | None = None,
) -> None:
    try:
        ensure_audit_table()
        record_ts = payload.get("ts") if isinstance(payload, dict) else None
        ts = datetime.now(timezone.utc) if not record_ts else datetime.fromisoformat(str(record_ts).replace("Z", "+00:00"))
        with pg_conn() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO platform_audit_log (ts, source, category, severity, status, target, classification, actor, payload)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
                """,
                (
                    ts,
                    source,
                    category,
                    severity,
                    status,
                    target,
                    classification,
                    actor,
                    json.dumps(payload),
                ),
            )
    except Exception as exc:
        logger.warning("Audit persistence failed", extra={"source": source, "category": category, "error": str(exc)})


def recent_audit_events(limit: int = 100, *, category: str | None = None) -> list[dict[str, Any]]:
    try:
        ensure_audit_table()
        query = """
            SELECT ts, source, category, severity, status, target, classification, actor, payload
            FROM platform_audit_log
        """
        params: list[Any] = []
        if category:
            query += " WHERE category = %s"
            params.append(category)
        query += " ORDER BY ts DESC LIMIT %s"
        params.append(limit)
        with pg_conn() as connection, connection.cursor() as cursor:
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    except Exception as exc:
        logger.warning("Audit query failed", extra={"category": category, "error": str(exc)})
        return []
