from __future__ import annotations

from services.shared.audit import ensure_audit_table
from services.shared.history import ensure_history_table
from services.shared.notifications import ensure_notification_tables


def migrate() -> None:
    ensure_audit_table()
    ensure_history_table()
    ensure_notification_tables()


if __name__ == "__main__":
    migrate()
