from __future__ import annotations

import unittest
from unittest.mock import patch

from tests._helpers import load_module


MODULE = load_module("services/chaos-engine/app/main.py", "chaos_engine_schedule_main")


class ChaosEngineTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        MODULE.history.clear()
        MODULE.experiments.clear()

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


if __name__ == "__main__":
    unittest.main()
