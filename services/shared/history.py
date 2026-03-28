from __future__ import annotations

import json
import logging
from threading import Lock
from typing import Any

from services.shared.store import ensure_table, pg_conn

logger = logging.getLogger("platform-history")
_table_ready = False
_table_lock = Lock()

HISTORY_DDL = """
CREATE TABLE IF NOT EXISTS platform_history_log (
    id BIGSERIAL PRIMARY KEY,
    stream TEXT NOT NULL,
    source TEXT NOT NULL,
    ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    payload JSONB NOT NULL
)
"""

HISTORY_INDEX_DDL = """
CREATE INDEX IF NOT EXISTS idx_platform_history_log_stream_ts
ON platform_history_log(stream, ts DESC, id DESC)
"""


def ensure_history_table() -> None:
    global _table_ready
    if _table_ready:
        return
    with _table_lock:
        if _table_ready:
            return
        with pg_conn() as connection:
            ensure_table(connection, HISTORY_DDL)
            ensure_table(connection, HISTORY_INDEX_DDL)
        _table_ready = True


def record_history(stream: str, source: str, payload: dict[str, Any]) -> None:
    try:
        ensure_history_table()
        with pg_conn() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO platform_history_log (stream, source, payload)
                VALUES (%s, %s, %s::jsonb)
                """,
                (stream, source, json.dumps(payload)),
            )
    except Exception as exc:
        logger.warning("History persistence failed", extra={"stream": stream, "source": source, "error": str(exc)})


def recent_history(stream: str, limit: int = 100) -> list[dict[str, Any]]:
    try:
        ensure_history_table()
        with pg_conn() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT payload
                FROM platform_history_log
                WHERE stream = %s
                ORDER BY id DESC
                LIMIT %s
                """,
                (stream, limit),
            )
            rows = cursor.fetchall()
        return [row["payload"] for row in reversed(rows)]
    except Exception as exc:
        logger.warning("History query failed", extra={"stream": stream, "error": str(exc)})
        return []
