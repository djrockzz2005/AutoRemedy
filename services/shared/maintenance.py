from __future__ import annotations

import logging
from typing import Iterable

from services.shared.store import pg_conn

logger = logging.getLogger("platform-maintenance")


def prune_tables(retention_days: int = 14) -> None:
    statements: Iterable[tuple[str, str]] = (
        ("platform_audit_log", "DELETE FROM platform_audit_log WHERE ts < NOW() - (%s || ' days')::interval"),
        ("platform_history_log", "DELETE FROM platform_history_log WHERE ts < NOW() - (%s || ' days')::interval"),
        ("notification_delivery_queue", "DELETE FROM notification_delivery_queue WHERE created_at < NOW() - (%s || ' days')::interval"),
    )
    try:
        with pg_conn() as connection, connection.cursor() as cursor:
            for table, sql in statements:
                cursor.execute(sql, (retention_days,))
                logger.info("Retention prune completed", extra={"table": table, "retention_days": retention_days})
    except Exception as exc:
        logger.warning("Retention prune failed", extra={"retention_days": retention_days, "error": str(exc)})
