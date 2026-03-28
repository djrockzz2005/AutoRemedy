from __future__ import annotations

import unittest
from unittest.mock import patch

from tests._helpers import load_module


MODULE = load_module("services/decision-engine/app/main.py", "decision_engine_main")


class FakeResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


class FakeAsyncClient:
    posted_payloads: list[tuple[str, dict]] = []

    def __init__(self, event_payload: dict | None = None, action_result: dict | None = None) -> None:
        self.event_payload = event_payload or {"items": []}
        self.action_result = action_result or {"status": "completed"}

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def get(self, url: str):
        return FakeResponse(self.event_payload)

    async def post(self, url: str, json: dict):
        self.posted_payloads.append((url, json))
        return FakeResponse({**self.action_result, **json})


class DecisionEngineTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        MODULE.processed.clear()
        MODULE.decisions.clear()
        MODULE.last_recovery_at.clear()
        MODULE.retry_counts.clear()
        MODULE.failure_streaks.clear()
        MODULE.circuit_open_until.clear()
        MODULE.playbooks = {}
        FakeAsyncClient.posted_payloads.clear()

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

        self.assertEqual(actions, [{"action": "restart_deployment", "target": "payment-service"}])

    def test_plan_actions_uses_service_specific_latency_target(self) -> None:
        event = {
            "classification": "latency_spike",
            "per_service": {
                "services": {
                    "api-gateway": {"latency_p95": 0.6},
                    "order-service": {"latency_p95": 1.4},
                }
            },
            "sample": {},
        }

        actions = MODULE.plan_actions(event)

        self.assertEqual(actions[0], {"action": "scale_deployment", "target": "order-service", "replicas": 3})
        self.assertEqual(actions[1], {"action": "reset_latency", "target": "order-service"})

    def test_plan_actions_reroutes_recommendation_service_error_burst(self) -> None:
        event = {
            "classification": "application_error_burst",
            "per_service": {
                "services": {
                    "recommendation-service": {"loki_errors": 9},
                    "api-gateway": {"loki_errors": 2},
                }
            },
            "sample": {},
        }

        actions = MODULE.plan_actions(event)

        self.assertEqual(
            actions,
            [
                {
                    "action": "reroute_service",
                    "service_name": "recommendation-service",
                    "selector_value": "shadow",
                },
                {"action": "restore_cache"},
            ],
        )

    def test_plan_actions_uses_loaded_playbook_when_present(self) -> None:
        MODULE.playbooks = {
            "pod_instability": [
                {"action": "restart_deployment", "target": "{target}"},
                {"action": "scale_deployment", "target": "{target}", "replicas": 2},
            ]
        }
        event = {
            "classification": "pod_instability",
            "per_service": {"services": {"inventory-service": {"restarts": 6}}},
            "sample": {},
        }

        actions = MODULE.plan_actions(event)

        self.assertEqual(
            actions,
            [
                {"action": "restart_deployment", "target": "inventory-service"},
                {"action": "scale_deployment", "target": "inventory-service", "replicas": 2},
            ],
        )

    def test_plan_actions_ddos_attack_applies_rate_limit_and_scaling(self) -> None:
        event = {
            "classification": "ddos_attack",
            "per_service": {"services": {"api-gateway": {"requests_per_ip_per_second": 40, "connection_count": 200}}},
            "sample": {},
        }

        actions = MODULE.plan_actions(event)

        self.assertEqual(actions[0]["action"], "apply_rate_limit")
        self.assertEqual(actions[0]["target"], "api-gateway")
        self.assertEqual(actions[1]["action"], "scale_under_ddos")

    def test_plan_actions_reorders_multi_step_playbook_from_feedback(self) -> None:
        MODULE.decisions.extend(
            [
                {
                    "event": {"classification": "availability_regression"},
                    "actions": [
                        {"action": "clear_network_partition", "target": "payment-service"},
                        {"action": "restart_deployment", "target": "payment-service"},
                    ],
                    "results": [
                        {"status": "failed"},
                        {"status": "completed"},
                    ],
                },
                {
                    "event": {"classification": "availability_regression"},
                    "actions": [
                        {"action": "clear_network_partition", "target": "payment-service"},
                        {"action": "restart_deployment", "target": "payment-service"},
                    ],
                    "results": [
                        {"status": "failed"},
                        {"status": "completed"},
                    ],
                },
            ]
        )
        event = {
            "classification": "availability_regression",
            "per_service": {"services": {"payment-service": {"availability": 0.82, "error_rate": 0.4}}},
            "sample": {},
        }

        with patch.object(MODULE, "recent_history", return_value=[]), patch.object(MODULE, "RL_EPSILON", 0.0):
            actions = MODULE.plan_actions(event)

        self.assertEqual(actions[0]["action"], "restart_deployment")
        self.assertEqual(actions[1]["action"], "clear_network_partition")

    def test_default_target_for_security_classifications(self) -> None:
        self.assertEqual(MODULE.default_target_for("mitm_attack"), "api-gateway")
        self.assertEqual(MODULE.default_target_for("clickjacking_attack"), "dashboard")
        self.assertEqual(MODULE.default_target_for("credential_stuffing_attack"), "dashboard")

    def test_plan_actions_for_session_hijacking_and_sqli(self) -> None:
        session_actions = MODULE.plan_actions({"classification": "session_hijacking_attack", "per_service": {"services": {"dashboard": {"session_hijack_attempt_count": 1}}}, "sample": {}})
        sqli_actions = MODULE.plan_actions({"classification": "sqli_attack", "per_service": {"services": {"api-gateway": {"sqli_attempt_count": 1}}}, "sample": {}})

        self.assertEqual(session_actions, [{"action": "quarantine_sessions", "target": "dashboard"}])
        self.assertEqual(sqli_actions, [{"action": "enable_sql_guard", "target": "api-gateway"}])

    def test_cooldown_suppresses_repeat_target(self) -> None:
        MODULE.last_recovery_at[("latency_spike", "api-gateway")] = MODULE.time.time()

        self.assertTrue(MODULE.is_in_cooldown("latency_spike", "api-gateway"))

    def test_circuit_breaker_opens_after_failure_threshold(self) -> None:
        classification = "pod_instability"
        target = "payment-service"

        for _ in range(MODULE.CIRCUIT_BREAKER_THRESHOLD):
            MODULE.mark_outcome(classification, target, succeeded=False)

        self.assertTrue(MODULE.circuit_is_open(classification, target))

    async def test_control_loop_fetches_events_and_posts_recovery_actions(self) -> None:
        event = {
            "ts": "2026-03-28T12:00:00+00:00",
            "classification": "pod_instability",
            "per_service": {"services": {"payment-service": {"restarts": 5}}},
            "sample": {},
        }

        clients = [
            FakeAsyncClient(event_payload={"items": [event]}),
            FakeAsyncClient(action_result={"status": "completed"}),
        ]

        async def stop_after_iteration(_seconds: float) -> None:
            raise RuntimeError("stop-loop")

        with patch.object(
            MODULE.httpx,
            "AsyncClient",
            side_effect=lambda timeout=5.0: clients.pop(0),
        ), patch.object(MODULE.asyncio, "sleep", side_effect=stop_after_iteration):
            with self.assertRaisesRegex(RuntimeError, "stop-loop"):
                await MODULE.control_loop()

        self.assertEqual(len(MODULE.decisions), 1)
        self.assertEqual(MODULE.decisions[0]["actions"][0]["target"], "payment-service")
        self.assertEqual(FakeAsyncClient.posted_payloads[0][0], f"{MODULE.RECOVERY_URL}/recover")
        self.assertEqual(FakeAsyncClient.posted_payloads[0][1]["reason"], "pod_instability")

    async def test_feedback_exposes_ranked_action_preferences(self) -> None:
        MODULE.decisions.extend(
            [
                {
                    "event": {"classification": "ddos_attack"},
                    "actions": [{"action": "apply_rate_limit", "target": "api-gateway"}],
                    "results": [{"status": "completed"}],
                },
                {
                    "event": {"classification": "ddos_attack"},
                    "actions": [{"action": "scale_under_ddos", "target": "api-gateway", "replicas": 6}],
                    "results": [{"status": "failed"}],
                },
            ]
        )

        with patch.object(MODULE, "recent_history", return_value=[]):
            payload = await MODULE.feedback()

        self.assertIn("ddos_attack", payload["action_preferences"])
        self.assertEqual(payload["action_preferences"]["ddos_attack"][0]["action"], "apply_rate_limit")


if __name__ == "__main__":
    unittest.main()
