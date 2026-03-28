from __future__ import annotations

import unittest

from tests._helpers import load_module


MODULE = load_module("services/telemetry-bridge/app/main.py", "telemetry_bridge_main")


class TelemetryBridgeTests(unittest.TestCase):
    def test_evaluate_slos_reports_compliance_and_violations(self) -> None:
        metrics = {
            "payment-service": {
                "latency_p95": 0.8,
                "error_rate": 0.02,
                "availability": 0.99,
            }
        }
        slos = {
            "payment-service": {
                "latency_p95_max": 0.5,
                "error_rate_max": 0.03,
                "availability_min": 0.995,
            }
        }

        status = MODULE.evaluate_slos(metrics, slos)

        self.assertEqual(len(status["items"]), 1)
        self.assertFalse(status["items"][0]["healthy"])
        self.assertIn("latency_p95", status["items"][0]["violations"])
        self.assertIn("availability", status["items"][0]["violations"])


if __name__ == "__main__":
    unittest.main()
