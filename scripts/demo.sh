#!/usr/bin/env bash
set -euo pipefail

KUBECTL="${KUBECTL:-.bin/kubectl}"
NAMESPACE="${NAMESPACE:-chaos-loop}"
DEMO_DURATION_SECONDS="${DEMO_DURATION_SECONDS:-60}"
POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-4}"
SCENARIO="${1:-ddos-simulation}"
TARGET="${2:-}"

declare -a PF_PIDS=()

start_port_forward() {
  local service_name="$1"
  local local_port="$2"
  local remote_port="$3"
  "${KUBECTL}" -n "${NAMESPACE}" port-forward "svc/${service_name}" "${local_port}:${remote_port}" >/tmp/"${service_name}"-pf.log 2>&1 &
  PF_PIDS+=("$!")
}

cleanup() {
  for pid in "${PF_PIDS[@]:-}"; do
    kill "${pid}" >/dev/null 2>&1 || true
  done
}

trap cleanup EXIT

start_port_forward dashboard 8080 8000
start_port_forward chaos-engine 8005 8000
start_port_forward anomaly-detector 8002 8000
start_port_forward decision-engine 8003 8000
start_port_forward recovery-engine 8004 8000
start_port_forward telemetry-bridge 8006 8000

sleep 4

echo "Live dashboard: http://localhost:8080"
echo "Scenario mode: ${SCENARIO}"
echo "Watch the dashboard while this script injects chaos, polls the control loop, and summarizes self-healing."

export DEMO_DURATION_SECONDS POLL_INTERVAL_SECONDS SCENARIO TARGET NAMESPACE
python3 - <<'PY'
import json
import os
import sys
import time
import urllib.error
import urllib.request
from http.client import RemoteDisconnected

duration = int(os.environ["DEMO_DURATION_SECONDS"])
poll = int(os.environ["POLL_INTERVAL_SECONDS"])
scenario_arg = os.environ["SCENARIO"]
override_target = os.environ["TARGET"]
namespace = os.environ["NAMESPACE"]

urls = {
    "chaos": "http://127.0.0.1:8005/scenarios",
    "events": "http://127.0.0.1:8002/events",
    "decisions": "http://127.0.0.1:8003/decisions",
    "feedback": "http://127.0.0.1:8003/feedback",
    "timeline": "http://127.0.0.1:8004/timeline",
    "features": "http://127.0.0.1:8006/features/latest",
}

SCENARIOS = {
    "ddos-simulation": {"target": "api-gateway", "classification": "ddos_attack"},
    "mitm-simulation": {"target": "api-gateway", "classification": "mitm_attack"},
    "xss-probe": {"target": "api-gateway", "classification": "xss_attack"},
    "clickjacking-probe": {"target": "dashboard", "classification": "clickjacking_attack"},
    "csrf-probe": {"target": "dashboard", "classification": "csrf_attack"},
    "session-hijack-probe": {"target": "dashboard", "classification": "session_hijacking_attack"},
    "credential-stuffing-probe": {"target": "dashboard", "classification": "credential_stuffing_attack"},
    "sqli-probe": {"target": "api-gateway", "classification": "sqli_attack"},
    "supply-chain-probe": {"target": "api-gateway", "classification": "supply_chain_attack"},
    "zero-day-probe": {"target": "api-gateway", "classification": "zero_day_attack"},
    "pod-crash": {"target": "order-service", "classification": "pod_instability"},
    "latency": {"target": "order-service", "classification": "latency_spike", "payload": {"latency_ms": 1500}},
    "network-partition": {"target": "payment-service", "classification": "availability_regression"},
    "resource-pressure": {"target": "order-service", "classification": "unknown_anomaly"},
}

SECURITY_ORDER = [
    "ddos-simulation",
    "mitm-simulation",
    "xss-probe",
    "clickjacking-probe",
    "csrf-probe",
    "session-hijack-probe",
    "credential-stuffing-probe",
    "sqli-probe",
    "supply-chain-probe",
    "zero-day-probe",
]

INFRA_ORDER = [
    "pod-crash",
    "latency",
    "network-partition",
    "resource-pressure",
]


def request_json(url: str, method: str = "GET", payload: dict | None = None, retries: int = 6, delay: float = 1.5) -> dict:
    body = None if payload is None else json.dumps(payload).encode()
    last_exc = None
    for attempt in range(1, retries + 1):
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=8) as response:
                return json.loads(response.read().decode())
        except (urllib.error.URLError, RemoteDisconnected, ConnectionResetError) as exc:
            last_exc = exc
            if attempt == retries:
                raise
            time.sleep(delay)
    raise RuntimeError(f"request failed: {last_exc}")


def resolve_run_list(selected: str) -> list[tuple[str, dict]]:
    if selected == "all":
        return [(name, SCENARIOS[name]) for name in SECURITY_ORDER + INFRA_ORDER]
    if selected == "attacks":
        return [(name, SCENARIOS[name]) for name in SECURITY_ORDER]
    if selected == "faults":
        return [(name, SCENARIOS[name]) for name in INFRA_ORDER]
    if selected in SCENARIOS:
        return [(selected, SCENARIOS[selected])]
    raise SystemExit(
        "Unsupported scenario '{}'. Try one of: {}, all, attacks, faults".format(
            selected,
            ", ".join(SCENARIOS.keys()),
        )
    )


def latest_matching(items: list[dict], classification: str) -> dict | None:
    matched = [item for item in items if item.get("classification") == classification]
    return matched[-1] if matched else None


def latest_decision(items: list[dict], classification: str, target_name: str) -> dict | None:
    candidates = []
    for item in items:
        event = item.get("event", {})
        if event.get("classification") != classification:
            continue
        action_targets = [action.get("target") or action.get("service_name") for action in item.get("actions", [])]
        if target_name in action_targets:
            candidates.append(item)
    return candidates[-1] if candidates else None


def latest_recovery(items: list[dict], classification: str, target_name: str) -> dict | None:
    candidates = [
        item for item in items
        if item.get("reason") == classification and item.get("target") == target_name
    ]
    return candidates[-1] if candidates else None


def metric_snapshot(payload: dict, classification: str, target_name: str) -> str:
    service_metrics = ((payload.get("per_service") or {}).get(target_name, {}) if isinstance(payload.get("per_service"), dict) else {}) or {}
    if classification == "ddos_attack":
        return "req/ip={:.0f}, conns={:.0f}, blocked={:.0f}".format(
            service_metrics.get("requests_per_ip_per_second", payload.get("requests_per_ip_per_second", 0.0)),
            service_metrics.get("connection_count", payload.get("connection_count", 0.0)),
            service_metrics.get("blocked_attempt_count", payload.get("blocked_attempt_count", 0.0)),
        )
    if classification == "xss_attack":
        return "xss={:.0f}, blocked={:.0f}".format(
            service_metrics.get("xss_attempt_count", payload.get("xss_attempt_count", 0.0)),
            service_metrics.get("blocked_attempt_count", payload.get("blocked_attempt_count", 0.0)),
        )
    if classification == "mitm_attack":
        return "tls_fail={:.0f}, cert_mismatch={:.0f}".format(
            service_metrics.get("tls_handshake_failures", payload.get("tls_handshake_failures", 0.0)),
            service_metrics.get("certificate_mismatch_count", payload.get("certificate_mismatch_count", 0.0)),
        )
    if classification in {"clickjacking_attack", "csrf_attack", "session_hijacking_attack", "credential_stuffing_attack"}:
        return "blocked={:.0f}, active_mitigations={:.0f}".format(
            service_metrics.get("blocked_attempt_count", payload.get("blocked_attempt_count", 0.0)),
            service_metrics.get("active_mitigations", payload.get("active_mitigations", 0.0)),
        )
    if classification in {"sqli_attack", "supply_chain_attack", "zero_day_attack"}:
        return "signals={:.0f}, blocked={:.0f}".format(
            max(
                service_metrics.get("sqli_attempt_count", 0.0),
                service_metrics.get("supply_chain_risk_count", 0.0),
                service_metrics.get("zero_day_signal_count", 0.0),
                0.0,
            ),
            service_metrics.get("blocked_attempt_count", payload.get("blocked_attempt_count", 0.0)),
        )
    return "restarts={:.0f}, latency_p95={:.2f}s".format(
        service_metrics.get("restarts", payload.get("restarts", 0.0)),
        service_metrics.get("latency_p95", payload.get("latency_p95", 0.0)),
    )


def print_step(prefix: str, elapsed: int, status: str, details: str) -> None:
    print(f"{prefix} [t+{elapsed:02d}s] {status:<10} {details}")


def run_demo(name: str, config: dict) -> dict:
    target = override_target or config["target"]
    expected = config["classification"]
    payload = {"target": target, "namespace": namespace}
    payload.update(config.get("payload", {}))

    try:
        injected = request_json(f"{urls['chaos']}/{name}", method="POST", payload=payload)
    except Exception as exc:
        return {
            "scenario": name,
            "target": target,
            "expected_classification": expected,
            "injected": False,
            "error": str(exc),
        }

    prefix = f"[{name}]"
    print_step(prefix, 0, "Injected", json.dumps({"target": target, "classification": expected}))

    first_event = None
    first_decision = None
    first_recovery = None
    last_actions = []

    for elapsed in range(poll, duration + poll, poll):
        try:
            events_payload = request_json(urls["events"], retries=3, delay=1.0)
            decisions_payload = request_json(urls["decisions"], retries=3, delay=1.0)
            timeline_payload = request_json(urls["timeline"], retries=3, delay=1.0)
            features_payload = request_json(urls["features"], retries=3, delay=1.0)
        except Exception as exc:
            print_step(prefix, elapsed, "Waiting", f"service unavailable: {exc}")
            time.sleep(poll)
            continue

        matching_event = latest_matching(events_payload.get("items", []), expected)
        matching_decision = latest_decision(decisions_payload.get("items", []), expected, target)
        matching_recovery = latest_recovery(timeline_payload.get("items", []), expected, target)

        if matching_event and first_event is None:
            first_event = elapsed
        if matching_decision and first_decision is None:
            first_decision = elapsed
            last_actions = [action.get("action", "unknown") for action in matching_decision.get("actions", [])]
        if matching_recovery and first_recovery is None:
            first_recovery = elapsed

        details = metric_snapshot(features_payload, expected, target)
        if matching_recovery:
            details = f"{details}; recovery={matching_recovery.get('action')}:{matching_recovery.get('status')}"
        elif matching_decision:
            details = f"{details}; planned={','.join(action.get('action', 'unknown') for action in matching_decision.get('actions', []))}"
        elif matching_event:
            details = f"{details}; detector classified {expected}"

        phase = "Watching"
        if matching_recovery:
            phase = "Recovered"
        elif matching_decision:
            phase = "Deciding"
        elif matching_event:
            phase = "Detected"
        print_step(prefix, min(elapsed, duration), phase, details)

        if elapsed >= duration:
            break
        time.sleep(poll)

    feedback = {}
    try:
        feedback = request_json(urls["feedback"], retries=3, delay=1.0)
    except Exception:
        feedback = {}

    return {
        "scenario": name,
        "target": target,
        "expected_classification": expected,
        "injected": injected.get("scenario") == name,
        "detected_within_demo": first_event is not None,
        "decision_within_demo": first_decision is not None,
        "recovered_within_demo": first_recovery is not None,
        "time_to_detection_seconds": first_event,
        "time_to_decision_seconds": first_decision,
        "time_to_recovery_seconds": first_recovery,
        "actions_observed": last_actions,
        "classification_feedback": (feedback.get("by_classification") or {}).get(expected, {}),
        "learned_action_preferences": (feedback.get("action_preferences") or {}).get(expected, []),
    }


run_list = resolve_run_list(scenario_arg)
summaries = []

print("Planned scenarios:")
for name, config in run_list:
    print(f"- {name} -> {config['classification']} on {override_target or config['target']}")

for index, (name, config) in enumerate(run_list, start=1):
    print(f"\n=== Demo {index}/{len(run_list)}: {name} ===")
    summaries.append(run_demo(name, config))

print("\nDemo summary")
print(json.dumps(summaries if len(summaries) > 1 else summaries[0], indent=2))

failed = [item for item in summaries if not item.get("injected")]
if failed:
    sys.exit(1)
PY
