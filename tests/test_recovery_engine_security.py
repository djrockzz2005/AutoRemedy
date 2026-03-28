from __future__ import annotations

import unittest

from tests._helpers import load_module


MODULE = load_module("services/recovery-engine/app/main.py", "recovery_engine_main")


class RecoveryEngineSecurityTests(unittest.TestCase):
    def test_security_signal_cleared_for_ddos(self) -> None:
        cleared = MODULE.security_signal_cleared(
            "ddos_attack",
            {"per_service": {"api-gateway": {"requests_per_ip_per_second": 1.0, "syn_flood_score": 0.02}}},
            "api-gateway",
        )

        self.assertTrue(cleared)

    def test_security_signal_not_cleared_for_mitm(self) -> None:
        cleared = MODULE.security_signal_cleared(
            "mitm_attack",
            {"per_service": {"api-gateway": {"tls_handshake_failures": 1.0}}},
            "api-gateway",
        )

        self.assertFalse(cleared)


if __name__ == "__main__":
    unittest.main()
