from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


def load_module(path: str, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


MODULE = load_module(str(Path("/home/guru/Dev/MITHack/services/decision-engine/app/main.py")), "decision_engine_main")


class DecisionEngineTests(unittest.TestCase):
    def test_plan_actions_uses_dynamic_restart_target(self) -> None:
        event = {
            "classification": "pod_instability",
            "per_service": {
                "services": {
                    "user-service": {"restarts": 1},
                    "payment-service": {"restarts": 4},
                }
            },
            "sample": {},
        }
        actions = MODULE.plan_actions(event)
        self.assertEqual(actions[0]["target"], "payment-service")

    def test_cooldown_suppresses_repeat_target(self) -> None:
        MODULE.last_recovery_at.clear()
        MODULE.last_recovery_at[("latency_spike", "api-gateway")] = MODULE.time.time()
        self.assertTrue(MODULE.is_in_cooldown("latency_spike", "api-gateway"))


if __name__ == "__main__":
    unittest.main()
