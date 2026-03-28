from __future__ import annotations

import importlib.util
import os
import sys
import types
import unittest
from pathlib import Path


def load_module():
    sys.path.insert(0, "/home/guru/Dev/MITHack")
    sys.modules["httpx"] = types.ModuleType("httpx")
    store = types.ModuleType("services.shared.store")
    store.ensure_table = lambda *args, **kwargs: None
    store.pg_conn = lambda *args, **kwargs: None
    sys.modules["services.shared.store"] = store
    spec = importlib.util.spec_from_file_location(
        "notifications_main",
        Path("/home/guru/Dev/MITHack/services/shared/notifications.py"),
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


MODULE = load_module()


class NotificationTests(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["PAGERDUTY_ROUTING_KEY"] = "routing-key"

    def test_slack_payload_formats_attachment(self) -> None:
        payload = MODULE.slack_payload(
            {
                "text": "[CRITICAL] detector: incident",
                "title": "incident",
                "source": "detector",
                "severity": "critical",
                "event_type": "anomaly_detected",
                "payload": {},
                "ts": "2026-03-28T00:00:00+00:00",
            }
        )
        self.assertEqual(payload["attachments"][0]["title"], "incident")

    def test_pagerduty_payload_includes_routing_key(self) -> None:
        payload = MODULE.pagerduty_payload(
            {
                "text": "[CRITICAL] detector: incident",
                "title": "incident",
                "source": "detector",
                "severity": "critical",
                "event_type": "anomaly_detected",
                "payload": {"target": "payment-service"},
                "ts": "2026-03-28T00:00:00+00:00",
            }
        )
        self.assertEqual(payload["routing_key"], "routing-key")
        self.assertEqual(payload["payload"]["component"], "anomaly_detected")

    def test_alertmanager_payload_uses_firing_status(self) -> None:
        payload = MODULE.alertmanager_payload(
            {
                "text": "[WARNING] engine: remediation",
                "title": "remediation",
                "source": "decision-engine",
                "severity": "warning",
                "event_type": "decision_executed",
                "payload": {},
                "ts": "2026-03-28T00:00:00+00:00",
            }
        )
        self.assertEqual(payload[0]["status"], "firing")
        self.assertEqual(payload[0]["labels"]["service"], "decision-engine")


if __name__ == "__main__":
    unittest.main()
