from __future__ import annotations

from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests._helpers import load_module


MODULE = load_module("services/anomaly-detector/app/main.py", "anomaly_detector_main")


class StubClassifier:
    def __init__(self, label: str) -> None:
        self.label = label

    def predict(self, matrix):
        return [self.label]


class FakeResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


class FakeAsyncClient:
    def __init__(self, payload: dict) -> None:
        self.payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def get(self, url: str):
        return FakeResponse(self.payload)


class AnomalyDetectorTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        MODULE.feature_window.clear()
        MODULE.scores.clear()
        MODULE.events.clear()
        MODULE.labeled_samples.clear()
        MODULE.classifier_model = None
        MODULE.isolation_model = None
        MODULE.last_model_train_size = 0
        MODULE.last_classifier_train_size = 0
        MODULE.last_event_ts = ""

    def test_build_vector_uses_feature_order_and_zero_defaults(self) -> None:
        vector = MODULE.build_vector({"request_rate": "7", "memory": 12})
        self.assertEqual(vector, [7.0, 0.0, 0.0, 0.0, 0.0, 12.0, 0.0, 0.0])

    def test_classify_prefers_trained_classifier_after_warmup(self) -> None:
        MODULE.classifier_model = StubClassifier("learned_label")
        MODULE.labeled_samples.extend({"vector": [], "label": "x"} for _ in range(MODULE.CLASSIFIER_MIN_SAMPLES))

        classification = MODULE.classify({"latency_p95": 9.0})

        self.assertEqual(classification, "learned_label")

    def test_classify_falls_back_to_rules_before_classifier_warmup(self) -> None:
        MODULE.classifier_model = StubClassifier("learned_label")

        classification = MODULE.classify({"latency_p95": 1.6})

        self.assertEqual(classification, "latency_spike")

    def test_build_service_vectors_extracts_per_service_metrics(self) -> None:
        vectors = MODULE.build_service_vectors(
            {
                "per_service": {
                    "payment-service": {"error_rate": 0.3, "availability": 0.95},
                    "api-gateway": {"latency_p95": 1.1},
                }
            }
        )

        self.assertEqual([item["service"] for item in vectors], ["payment-service", "api-gateway"])
        self.assertEqual(vectors[0]["vector"][1], 0.3)

    async def test_detect_loop_records_event_from_mocked_telemetry(self) -> None:
        sample = {
            "ts": "2026-03-28T12:00:00+00:00",
            "request_rate": 0.2,
            "error_rate": 0.7,
            "latency_p95": 0.0,
            "restarts": 0.0,
            "cpu": 0.1,
            "memory": 0.2,
            "loki_errors": 0.0,
            "availability": 0.6,
            "per_service": {
                "payment-service": {"error_rate": 0.7, "availability": 0.6},
            },
        }

        async def stop_after_iteration(_seconds: float) -> None:
            raise RuntimeError("stop-loop")

        with patch.object(MODULE, "THRESHOLD", 0.5), patch.object(MODULE, "should_retrain", return_value=False), patch.object(
            MODULE.httpx,
            "AsyncClient",
            side_effect=lambda timeout=4.0: FakeAsyncClient(sample),
        ), patch.object(MODULE.asyncio, "sleep", side_effect=stop_after_iteration):
            with self.assertRaisesRegex(RuntimeError, "stop-loop"):
                await MODULE.detect_loop()

        self.assertEqual(len(MODULE.scores), 1)
        self.assertEqual(len(MODULE.events), 1)
        self.assertEqual(MODULE.events[0]["classification"], "availability_regression")
        self.assertEqual(MODULE.events[0]["target_service"], "payment-service")
        self.assertEqual(MODULE.events[0]["per_service"]["top_error_services"][0][0], "payment-service")


if __name__ == "__main__":
    unittest.main()
