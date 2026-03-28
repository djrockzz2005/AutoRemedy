from __future__ import annotations

import unittest
from unittest.mock import patch

from tests._helpers import load_module


ANOMALY_MODULE = load_module("services/anomaly-detector/app/main.py", "anomaly_detector_e2e")
DECISION_MODULE = load_module("services/decision-engine/app/main.py", "decision_engine_e2e")


class FakeResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


class TelemetryClient:
    def __init__(self, sample: dict) -> None:
        self.sample = sample

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def get(self, url: str):
        return FakeResponse(self.sample)


class DecisionClient:
    posted: list[dict] = []

    def __init__(self, event_payload: dict | None = None) -> None:
        self.event_payload = event_payload or {"items": []}

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def get(self, url: str):
        return FakeResponse(self.event_payload)

    async def post(self, url: str, json: dict):
        self.posted.append(json)
        return FakeResponse({"status": "completed", **json})


class ObserveDecideActTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        ANOMALY_MODULE.feature_window.clear()
        ANOMALY_MODULE.scores.clear()
        ANOMALY_MODULE.events.clear()
        ANOMALY_MODULE.labeled_samples.clear()
        ANOMALY_MODULE.classifier_model = None
        ANOMALY_MODULE.isolation_model = None
        ANOMALY_MODULE.last_event_ts = ""

        DECISION_MODULE.processed.clear()
        DECISION_MODULE.decisions.clear()
        DECISION_MODULE.last_recovery_at.clear()
        DecisionClient.posted.clear()

    async def test_observe_decide_act_loop_flows_from_telemetry_to_recovery(self) -> None:
        sample = {
            "ts": "2026-03-28T12:00:00+00:00",
            "request_rate": 0.1,
            "error_rate": 0.9,
            "latency_p95": 0.2,
            "restarts": 0.0,
            "cpu": 0.1,
            "memory": 0.2,
            "loki_errors": 0.0,
            "availability": 0.1,
            "per_service": {
                "payment-service": {
                    "error_rate": 0.9,
                    "availability": 0.1,
                }
            },
        }

        async def stop_after_iteration(_seconds: float) -> None:
            raise RuntimeError("stop-loop")

        with patch.object(ANOMALY_MODULE, "THRESHOLD", 0.5), patch.object(
            ANOMALY_MODULE,
            "should_retrain",
            return_value=False,
        ), patch.object(
            ANOMALY_MODULE.httpx,
            "AsyncClient",
            side_effect=lambda timeout=4.0: TelemetryClient(sample),
        ), patch.object(ANOMALY_MODULE.asyncio, "sleep", side_effect=stop_after_iteration):
            with self.assertRaisesRegex(RuntimeError, "stop-loop"):
                await ANOMALY_MODULE.detect_loop()

        decision_clients = [
            DecisionClient(event_payload={"items": list(ANOMALY_MODULE.events)}),
            DecisionClient(),
        ]

        with patch.object(
            DECISION_MODULE.httpx,
            "AsyncClient",
            side_effect=lambda timeout=5.0: decision_clients.pop(0),
        ), patch.object(DECISION_MODULE.asyncio, "sleep", side_effect=stop_after_iteration):
            with self.assertRaisesRegex(RuntimeError, "stop-loop"):
                await DECISION_MODULE.control_loop()

        self.assertEqual(len(ANOMALY_MODULE.events), 1)
        self.assertEqual(ANOMALY_MODULE.events[0]["classification"], "availability_regression")
        self.assertEqual(len(DECISION_MODULE.decisions), 1)
        self.assertEqual(DecisionClient.posted[0]["action"], "clear_network_partition")
        self.assertEqual(DecisionClient.posted[1]["action"], "restart_deployment")
        self.assertTrue(all(item["target"] == "payment-service" for item in DecisionClient.posted))


if __name__ == "__main__":
    unittest.main()
