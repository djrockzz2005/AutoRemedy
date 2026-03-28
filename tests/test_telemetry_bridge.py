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
                "tls_handshake_failures": 1,
            }
        }
        slos = {
            "payment-service": {
                "latency_p95_max": 0.5,
                "error_rate_max": 0.03,
                "availability_min": 0.995,
                "tls_handshake_failures_max": 0,
            }
        }

        status = MODULE.evaluate_slos(metrics, slos)

        self.assertEqual(len(status["items"]), 1)
        self.assertFalse(status["items"][0]["healthy"])
        self.assertIn("latency_p95", status["items"][0]["violations"])
        self.assertIn("availability", status["items"][0]["violations"])
        self.assertIn("tls_handshake_failures", status["items"][0]["violations"])

    def test_apply_security_snapshot_merges_security_metrics(self) -> None:
        original = MODULE.cluster_security_snapshot
        MODULE.cluster_security_snapshot = lambda services=None: (
            {"xss_attempt_count": 3.0},
            {"api-gateway": {"blocked_attempt_count": 5.0, "requests_per_ip_per_second": 12.0}},
        )
        try:
            sample, per_service = MODULE.apply_security_snapshot({}, {"api-gateway": {"request_rate": 1.0}})
        finally:
            MODULE.cluster_security_snapshot = original

        self.assertEqual(sample["xss_attempt_count"], 3.0)
        self.assertEqual(per_service["api-gateway"]["blocked_attempt_count"], 5.0)


if __name__ == "__main__":
    unittest.main()
