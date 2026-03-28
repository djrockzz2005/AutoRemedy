from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from tests._helpers import load_module


class FakeAsyncClient:
    def __init__(self, *args, **kwargs) -> None:
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None


class FakeResponse:
    def __init__(self, payload: dict, error: str | None = None) -> None:
        self.payload = payload
        self.error = error

    def raise_for_status(self) -> None:
        if self.error:
            raise RuntimeError(self.error)

    def json(self) -> dict:
        return self.payload


class DashboardSnapshotTests(unittest.TestCase):
    def test_snapshot_payload_falls_back_when_dependencies_fail(self) -> None:
        module = load_module("services/dashboard/app/main.py", "dashboard_main_snapshot_fallback")

        responses = {
            f"{module.DETECTOR_URL}/scores": FakeResponse({"items": [{"ts": "2026-03-28T10:00:00", "score": 0.42, "sample": {}}]}),
            f"{module.DETECTOR_URL}/events": FakeResponse({}, error="detector unavailable"),
            f"{module.DECISION_URL}/decisions": FakeResponse({"items": [{"event": {"classification": "latency_spike"}, "actions": []}]}),
            f"{module.RECOVERY_URL}/timeline": FakeResponse({}, error="recovery unavailable"),
            f"{module.TELEMETRY_URL}/slo/status": FakeResponse({"overall_compliance": 98, "items": [{"service": "api", "healthy": True}]}),
            f"{module.CHAOS_URL}/experiments": FakeResponse({}, error="chaos unavailable"),
        }

        async def fake_traced_get(_client, url, **kwargs):
            return responses[url]

        with patch.object(module.httpx, "AsyncClient", FakeAsyncClient), patch.object(module, "traced_get", side_effect=fake_traced_get), patch.object(
            module, "list_workloads", side_effect=RuntimeError("kube unavailable")
        ):
            payload = asyncio.run(module.snapshot_payload())

        self.assertEqual(len(payload["scores"]), 1)
        self.assertEqual(payload["events"], [])
        self.assertEqual(len(payload["decisions"]), 1)
        self.assertEqual(payload["timeline"], [])
        self.assertEqual(payload["slos"]["overall_compliance"], 98)
        self.assertEqual(payload["experiments"], [])
        self.assertEqual(payload["workloads"], [])
        self.assertEqual(
            {item["name"] for item in payload["unavailable"]},
            {"events", "timeline", "experiments", "workloads"},
        )


if __name__ == "__main__":
    unittest.main()
