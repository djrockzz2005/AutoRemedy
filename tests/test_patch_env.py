from __future__ import annotations

from types import SimpleNamespace
import unittest

from tests._helpers import load_module


RECOVERY_MODULE = load_module("services/recovery-engine/app/main.py", "recovery_engine_main")
CHAOS_MODULE = load_module("services/chaos-engine/app/main.py", "chaos_engine_main")


def container(name: str, env: list[tuple[str, str]]):
    return SimpleNamespace(
        name=name,
        env=[SimpleNamespace(name=key, value=value) for key, value in env],
    )


class PatchEnvTests(unittest.TestCase):
    def test_recovery_patch_env_replaces_existing_value_and_preserves_other_env(self) -> None:
        patches = RECOVERY_MODULE.patch_env(
            [container("api", [("LATENCY_MS", "1500"), ("MODE", "prod")])],
            None,
            "LATENCY_MS",
            "0",
        )

        self.assertEqual(
            patches,
            [
                {
                    "name": "api",
                    "env": [
                        {"name": "MODE", "value": "prod"},
                        {"name": "LATENCY_MS", "value": "0"},
                    ],
                }
            ],
        )

    def test_chaos_patch_env_only_updates_selected_container(self) -> None:
        patches = CHAOS_MODULE.patch_env(
            [
                container("api", [("MODE", "prod")]),
                container("worker", [("MODE", "prod")]),
            ],
            "worker",
            "LATENCY_MS",
            "900",
        )

        self.assertEqual(
            patches,
            [
                {
                    "name": "worker",
                    "env": [
                        {"name": "MODE", "value": "prod"},
                        {"name": "LATENCY_MS", "value": "900"},
                    ],
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
