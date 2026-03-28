from __future__ import annotations

import unittest
from unittest.mock import patch

from tests._helpers import install_test_stubs, load_module

install_test_stubs()
from services.shared import security as security_module


MODULE = load_module("services/chaos-engine/app/main.py", "chaos_engine_schedule_main")


class ChaosEngineTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        MODULE.history.clear()
        MODULE.experiments.clear()
        security_module._MEMORY_STATE.clear()
        security_module.redis_json_get = lambda _client, key, default=None: security_module._MEMORY_STATE.get(
            str(key).split("security:telemetry:", 1)[-1],
            default,
        )
        security_module.redis_json_set = lambda _client, key, value: security_module._MEMORY_STATE.__setitem__(
            str(key).split("security:telemetry:", 1)[-1],
            value,
        )
        security_module.redis_client = lambda: (_ for _ in ()).throw(RuntimeError("redis unavailable in tests"))

    async def test_execute_experiment_records_heal_outcome(self) -> None:
        plan = {
            "name": "latency-drill",
            "target": "api-gateway",
            "observe_seconds": 0,
            "steps": [
                {"scenario": "latency", "payload": {"latency_ms": 900}},
            ],
        }

        with patch.object(MODULE, "run_scenario_by_name", return_value={"status": "injected"}), patch.object(
            MODULE,
            "evaluate_experiment",
            return_value={"healed": True, "reason": "slo_healthy"},
        ):
            result = await MODULE.execute_experiment(plan)

        self.assertEqual(result["name"], "latency-drill")
        self.assertTrue(result["evaluation"]["healed"])
        self.assertEqual(len(MODULE.experiments), 1)

    async def test_ddos_simulation_injects_security_telemetry(self) -> None:
        request = MODULE.ScenarioRequest(target="api-gateway")

        result = await MODULE.ddos_simulation(request)
        aggregate, per_service = security_module.cluster_security_snapshot(["api-gateway"])

        self.assertEqual(result["scenario"], "ddos-simulation")
        self.assertGreaterEqual(per_service["api-gateway"]["requests_per_ip_per_second"], 25.0)
        self.assertGreaterEqual(per_service["api-gateway"]["connection_count"], 150.0)
        self.assertGreaterEqual(aggregate["blocked_attempt_count"], 1.0)

    async def test_xss_probe_injects_security_telemetry(self) -> None:
        request = MODULE.ScenarioRequest(target="api-gateway")

        result = await MODULE.xss_probe(request)
        _, per_service = security_module.cluster_security_snapshot(["api-gateway"])

        self.assertEqual(result["scenario"], "xss-probe")
        self.assertGreaterEqual(per_service["api-gateway"]["xss_attempt_count"], 1.0)
        self.assertGreaterEqual(per_service["api-gateway"]["blocked_attempt_count"], 1.0)


if __name__ == "__main__":
    unittest.main()
