from __future__ import annotations

import asyncio
import json
import math
import os
from collections import deque
from pathlib import Path
from typing import Any

import httpx
import joblib
import numpy as np
from fastapi import FastAPI
from sklearn.ensemble import IsolationForest
from sklearn.tree import DecisionTreeClassifier

from services.shared.audit import audit_event
from services.shared.history import record_history, recent_history
from services.shared.notifications import notification_worker, notify
from services.shared.observability import install_observability, traced_get

app = FastAPI(title="anomaly-detector")
logger = install_observability(app, "anomaly-detector")

TELEMETRY_URL = os.getenv("TELEMETRY_URL", "http://telemetry-bridge:8000")
WINDOW = int(os.getenv("MODEL_WINDOW", "80"))
THRESHOLD = float(os.getenv("ANOMALY_THRESHOLD", "0.58"))
DETECT_INTERVAL = float(os.getenv("DETECT_INTERVAL_SECONDS", "2"))
RETRAIN_INTERVAL = int(os.getenv("RETRAIN_INTERVAL", "10"))
CLASSIFIER_MIN_SAMPLES = int(os.getenv("CLASSIFIER_MIN_SAMPLES", "30"))
MODEL_PATH = Path(os.getenv("MODEL_PATH", "/tmp/model.pkl"))
CLASSIFIER_MODEL_PATH = Path(os.getenv("CLASSIFIER_MODEL_PATH", "/tmp/classifier.pkl"))
BASELINE_STATS_PATH = Path(os.getenv("BASELINE_STATS_PATH", "/tmp/model-baseline.json"))
MIN_ACTIVE_REQUEST_RATE = float(os.getenv("MIN_ACTIVE_REQUEST_RATE", "0.02"))
MIN_ACTIVE_LATENCY = float(os.getenv("MIN_ACTIVE_LATENCY", "0.02"))

feature_window: deque[dict] = deque(maxlen=WINDOW)
scores: deque[dict] = deque(maxlen=200)
events: deque[dict] = deque(maxlen=100)
labeled_samples: deque[dict] = deque(maxlen=500)
service_feature_window: deque[dict] = deque(maxlen=WINDOW * 8)
service_scores: deque[dict] = deque(maxlen=400)
last_event_ts = ""
isolation_model: IsolationForest | None = None
classifier_model: DecisionTreeClassifier | None = None
service_isolation_model: IsolationForest | None = None
last_model_train_size = 0
last_classifier_train_size = 0
last_service_model_train_size = 0
baseline_mean: list[float] = []

FEATURE_KEYS = [
    "request_rate",
    "error_rate",
    "latency_p95",
    "restarts",
    "cpu",
    "memory",
    "loki_errors",
    "availability",
    "requests_per_ip_per_second",
    "unique_source_ips",
    "connection_count",
    "syn_flood_score",
    "tls_handshake_failures",
    "certificate_mismatch_count",
    "unexpected_certificate_fingerprints",
    "xss_attempt_count",
    "clickjack_attempt_count",
    "csrf_attempt_count",
    "blocked_attempt_count",
    "request_rate_peak_per_endpoint",
    "active_mitigations",
]


def build_vector(sample: dict) -> list[float]:
    return [float(sample.get(key, 0.0)) for key in FEATURE_KEYS]


def rule_based_classify(sample: dict) -> str:
    request_rate = float(sample.get("request_rate", 0.0))
    single_ip_rate = float(sample.get("requests_per_ip_per_second", 0.0))
    unique_ips = float(sample.get("unique_source_ips", 0.0))
    total_connections = float(sample.get("connection_count", 0.0))
    unique_ip_ratio = unique_ips / max(total_connections, 1.0)
    if (
        single_ip_rate >= float(os.getenv("DDOS_ATTACK_IP_RATE_THRESHOLD", "25"))
        or total_connections >= float(os.getenv("DDOS_CONNECTION_COUNT_THRESHOLD", "150"))
        or sample.get("syn_flood_score", 0.0) >= float(os.getenv("DDOS_SYN_FLOOD_SCORE_THRESHOLD", "0.4"))
        or (request_rate > 0 and unique_ip_ratio >= float(os.getenv("DDOS_UNIQUE_IP_RATIO_THRESHOLD", "0.65")))
    ):
        return "ddos_attack"
    if (
        float(sample.get("tls_handshake_failures", 0.0)) > 0.0
        or float(sample.get("certificate_mismatch_count", 0.0)) > 0.0
        or float(sample.get("unexpected_certificate_fingerprints", 0.0)) > 0.0
    ):
        return "mitm_attack"
    if float(sample.get("xss_attempt_count", 0.0)) >= float(os.getenv("XSS_ATTACK_THRESHOLD", "1")):
        return "xss_attack"
    if float(sample.get("clickjack_attempt_count", 0.0)) >= float(os.getenv("CLICKJACK_ATTACK_THRESHOLD", "1")):
        return "clickjacking_attack"
    if float(sample.get("csrf_attempt_count", 0.0)) >= float(os.getenv("CSRF_ATTACK_THRESHOLD", "1")):
        return "csrf_attack"
    if sample.get("error_rate", 0) > 0.5 or sample.get("availability", 1) < 0.9:
        return "availability_regression"
    if sample.get("latency_p95", 0) > 1.2:
        return "latency_spike"
    if sample.get("restarts", 0) > 0:
        return "pod_instability"
    if sample.get("loki_errors", 0) > 4:
        return "application_error_burst"
    return "unknown_anomaly"


def should_retrain(current_size: int, last_size: int, minimum_size: int) -> bool:
    return current_size >= minimum_size and (last_size == 0 or current_size - last_size >= RETRAIN_INTERVAL)


def load_models() -> None:
    global isolation_model, classifier_model, baseline_mean
    if MODEL_PATH.exists():
        try:
            isolation_model = joblib.load(MODEL_PATH)
        except Exception:
            isolation_model = None
    if CLASSIFIER_MODEL_PATH.exists():
        try:
            classifier_model = joblib.load(CLASSIFIER_MODEL_PATH)
        except Exception:
            classifier_model = None
    if BASELINE_STATS_PATH.exists():
        try:
            baseline_mean = list(json.loads(BASELINE_STATS_PATH.read_text()).get("baseline_mean", []))
        except Exception:
            baseline_mean = []


def train_isolation_model() -> None:
    global isolation_model, last_model_train_size, baseline_mean
    matrix = np.array([build_vector(item) for item in feature_window])
    contamination = min(0.2, max(0.05, 4.0 / len(feature_window)))
    isolation_model = IsolationForest(random_state=42, contamination=contamination)
    isolation_model.fit(matrix)
    last_model_train_size = len(feature_window)
    baseline_mean = [float(sum(item[idx] for item in matrix) / len(matrix)) for idx in range(len(FEATURE_KEYS))]
    try:
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(isolation_model, MODEL_PATH)
        BASELINE_STATS_PATH.write_text(json.dumps({"baseline_mean": baseline_mean}))
    except Exception:
        logger.warning("Failed to persist isolation model", extra={"path": str(MODEL_PATH)})


def train_service_isolation_model() -> None:
    global service_isolation_model, last_service_model_train_size
    matrix = np.array([item["vector"] for item in service_feature_window])
    contamination = min(0.2, max(0.05, 4.0 / len(service_feature_window)))
    service_isolation_model = IsolationForest(random_state=42, contamination=contamination)
    service_isolation_model.fit(matrix)
    last_service_model_train_size = len(service_feature_window)


def train_classifier_model() -> None:
    global classifier_model, last_classifier_train_size
    features = np.array([item["vector"] for item in labeled_samples])
    labels = np.array([item["label"] for item in labeled_samples])
    classifier_model = DecisionTreeClassifier(max_depth=5, random_state=42)
    classifier_model.fit(features, labels)
    last_classifier_train_size = len(labeled_samples)
    try:
        CLASSIFIER_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(classifier_model, CLASSIFIER_MODEL_PATH)
    except Exception:
        logger.warning("Failed to persist classifier model", extra={"path": str(CLASSIFIER_MODEL_PATH)})


def classify(sample: dict) -> str:
    vector = np.array([build_vector(sample)])
    if classifier_model is not None and len(labeled_samples) >= CLASSIFIER_MIN_SAMPLES:
        try:
            return str(classifier_model.predict(vector)[0])
        except Exception:
            logger.warning("Classifier inference failed; falling back to rules")
    return rule_based_classify(sample)


def annotate_per_service(sample: dict) -> dict[str, Any]:
    per_service = sample.get("per_service", {}) or {}
    if not isinstance(per_service, dict):
        return {}
    ranked = {}
    for metric in ("restarts", "latency_p95", "error_rate", "availability", "loki_errors"):
        if metric == "availability":
            sort_key = lambda item: item[1].get(metric, 1.0)
            reverse = False
        else:
            sort_key = lambda item: item[1].get(metric, 0.0)
            reverse = True
        ranked[metric] = sorted(per_service.items(), key=sort_key, reverse=reverse)[:3]
    return {
        "services": per_service,
        "top_restart_services": ranked["restarts"],
        "top_latency_services": ranked["latency_p95"],
        "top_error_services": ranked["error_rate"],
        "lowest_availability_services": ranked["availability"],
        "top_loki_error_services": ranked["loki_errors"],
        "top_ddos_services": sorted(
            per_service.items(),
            key=lambda item: item[1].get("requests_per_ip_per_second", 0.0) + item[1].get("syn_flood_score", 0.0),
            reverse=True,
        )[:3],
        "top_security_services": sorted(
            per_service.items(),
            key=lambda item: item[1].get("xss_attempt_count", 0.0)
            + item[1].get("csrf_attempt_count", 0.0)
            + item[1].get("clickjack_attempt_count", 0.0)
            + item[1].get("tls_handshake_failures", 0.0),
            reverse=True,
        )[:3],
    }


def build_service_vectors(sample: dict) -> list[dict[str, Any]]:
    per_service = sample.get("per_service", {}) or {}
    vectors = []
    for service, metrics in per_service.items():
        if not isinstance(metrics, dict):
            continue
        vectors.append({"service": service, "vector": build_vector(metrics), "sample": metrics})
    return vectors


def score_service_vector(service_sample: dict[str, Any]) -> float:
    vector = service_sample["vector"]
    if service_isolation_model is not None and len(service_feature_window) >= 20:
        decision = service_isolation_model.decision_function(np.array([vector]))[0]
        return float(1 / (1 + math.exp(decision * 3)))
    metrics = service_sample["sample"]
    return float(min(1.0, metrics.get("error_rate", 0.0) + metrics.get("latency_p95", 0.0) + metrics.get("restarts", 0.0)))


def classify_service(service: dict[str, Any], aggregate_sample: dict) -> str:
    merged = {**aggregate_sample, **service["sample"]}
    return classify(merged)


def current_drift_score() -> float:
    if not baseline_mean or not feature_window:
        return 0.0
    current_mean = [
        float(sum(float(item.get(key, 0.0)) for item in feature_window) / len(feature_window))
        for key in FEATURE_KEYS
    ]
    return round(math.sqrt(sum((current_mean[idx] - baseline_mean[idx]) ** 2 for idx in range(len(FEATURE_KEYS)))), 4)


def low_signal_sample(sample: dict) -> bool:
    if sample.get("collector_error"):
        return True
    return (
        float(sample.get("request_rate", 0.0)) <= MIN_ACTIVE_REQUEST_RATE
        and float(sample.get("error_rate", 0.0)) <= 0.0
        and float(sample.get("latency_p95", 0.0)) <= MIN_ACTIVE_LATENCY
        and float(sample.get("restarts", 0.0)) <= 0.0
        and float(sample.get("loki_errors", 0.0)) <= 0.0
        and float(sample.get("xss_attempt_count", 0.0)) <= 0.0
        and float(sample.get("csrf_attempt_count", 0.0)) <= 0.0
        and float(sample.get("clickjack_attempt_count", 0.0)) <= 0.0
        and float(sample.get("tls_handshake_failures", 0.0)) <= 0.0
        and float(sample.get("requests_per_ip_per_second", 0.0)) <= 0.0
    )


async def detect_loop() -> None:
    global last_event_ts
    while True:
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                response = await traced_get(client, f"{TELEMETRY_URL}/features/latest")
                response.raise_for_status()
                sample = response.json()
        except Exception as exc:
            logger.warning("Detector fetch failed", extra={"error": str(exc)})
            await asyncio.sleep(DETECT_INTERVAL)
            continue

        if not sample or sample.get("ts") == last_event_ts:
            await asyncio.sleep(DETECT_INTERVAL)
            continue

        feature_window.append(sample)
        vector = build_vector(sample)
        anomaly_score = 0.0
        if should_retrain(len(feature_window), last_model_train_size, 20):
            train_isolation_model()
        per_service_vectors = build_service_vectors(sample)
        for item in per_service_vectors:
            service_feature_window.append(item)
        if should_retrain(len(service_feature_window), last_service_model_train_size, 20):
            train_service_isolation_model()
        if low_signal_sample(sample):
            anomaly_score = 0.0
        elif isolation_model is not None and len(feature_window) >= 20:
            decision = isolation_model.decision_function(np.array([vector]))[0]
            anomaly_score = 1 / (1 + math.exp(decision * 3))
        else:
            anomaly_score = min(1.0, sample.get("error_rate", 0) + sample.get("latency_p95", 0))
        ranked_services = []
        for item in per_service_vectors:
            service_score = round(score_service_vector(item), 4)
            ranked_services.append(
                {
                    "service": item["service"],
                    "score": service_score,
                    "classification": classify_service(item, sample),
                    "sample": item["sample"],
                }
            )
        ranked_services.sort(key=lambda item: item["score"], reverse=True)
        if ranked_services:
            service_score_entry = {"ts": sample["ts"], "items": ranked_services[:5]}
            service_scores.append(service_score_entry)
            record_history("anomaly-service-scores", "anomaly-detector", service_score_entry)

        score = {"ts": sample["ts"], "score": round(float(anomaly_score), 4), "sample": sample}
        scores.append(score)
        record_history("anomaly-scores", "anomaly-detector", score)
        audit_event(
            "anomaly-detector",
            "anomaly-score",
            score,
            severity="info",
            classification=sample.get("classification"),
        )
        if anomaly_score >= THRESHOLD:
            classification = classify(sample)
            target_service = ranked_services[0]["service"] if ranked_services else None
            service_classification = ranked_services[0]["classification"] if ranked_services else classification
            event = {
                "ts": sample["ts"],
                "score": round(float(anomaly_score), 4),
                "classification": service_classification,
                "sample": sample,
                "per_service": annotate_per_service(sample),
                "service_scores": ranked_services[:5],
                "target_service": target_service,
                "aggregate_classification": classification,
            }
            events.append(event)
            record_history("anomaly-events", "anomaly-detector", event)
            labeled_samples.append({"vector": vector, "label": service_classification})
            if should_retrain(len(labeled_samples), last_classifier_train_size, CLASSIFIER_MIN_SAMPLES):
                train_classifier_model()
            severity = "critical" if anomaly_score >= max(0.85, THRESHOLD + 0.15) else "warning"
            audit_event(
                "anomaly-detector",
                "anomaly-event",
                event,
                severity=severity,
                status="detected",
                target=event.get("per_service", {}).get("top_error_services", [[None]])[0][0] if event.get("per_service") else None,
                classification=classification,
            )
            await notify(
                "anomaly-detector",
                "anomaly_detected",
                severity,
                f"{service_classification} detected for {target_service or 'cluster'} at score {event['score']}",
                event,
            )
            logger.warning("Anomaly detected", extra=event)
        last_event_ts = sample["ts"]
        await asyncio.sleep(DETECT_INTERVAL)


@app.on_event("startup")
async def startup() -> None:
    load_models()
    asyncio.create_task(notification_worker())
    asyncio.create_task(detect_loop())


@app.get("/status")
async def status() -> dict:
    return {"window": len(feature_window), "last_score": scores[-1] if scores else None}


@app.get("/model/metrics")
async def model_metrics() -> dict:
    recent = list(scores)[-20:]
    anomaly_rate = round(sum(1 for item in recent if item.get("score", 0.0) >= THRESHOLD) / len(recent), 4) if recent else 0.0
    return {
        "window": len(feature_window),
        "labeled_samples": len(labeled_samples),
        "last_model_train_size": last_model_train_size,
        "last_classifier_train_size": last_classifier_train_size,
        "last_service_model_train_size": last_service_model_train_size,
        "anomaly_rate_recent": anomaly_rate,
        "drift_score": current_drift_score(),
        "baseline_ready": bool(baseline_mean),
    }


@app.get("/scores")
async def score_history() -> dict:
    return {"items": recent_history("anomaly-scores", 200) or list(scores)}


@app.get("/events")
async def event_history() -> dict:
    return {"items": recent_history("anomaly-events", 100) or list(events)}


@app.get("/scores/per-service")
async def per_service_scores() -> dict:
    return {"items": recent_history("anomaly-service-scores", 400) or list(service_scores)}
